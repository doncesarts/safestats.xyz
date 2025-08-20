import axios from 'axios'
import pRetry from 'p-retry'
import { BigNumber, Contract, providers, Transaction, utils } from 'ethers'
import GnosisSafe from 'utils/abis/GnosisSafe.json'

// This code was inspired by the "checkNSignatures" function in the Gnosis Safe contract
export const recoverAddress = (dataHashStr: string, signature: string) => {
  const dataHash = utils.arrayify(dataHashStr)
  const { v, r, s } = utils.splitSignature(signature)

  // Ethers adjusts the "v" when it is 1 or 0
  const unadjustedV = signature.slice(-2)

  // For contract signatures and approved hashes, the address is encoded in "r"
  if (unadjustedV === '00' || unadjustedV === '01') {
    return utils.getAddress(utils.hexDataSlice(r, 12))
  }

  // If v > 30, this is an eth_sign message
  if (v > 30) {
    return utils.verifyMessage(dataHash, { v: v - 4, r, s })
  }

  return utils.recoverAddress(dataHash, { v, r, s })
}

// Decoder function type for different transaction types
type TransactionDecoder = (
  transaction: Transaction,
  nonce: number,
  provider: providers.JsonRpcProvider,
  iface: utils.Interface
) => Promise<string[]>

// Decoder for execTransaction calls
const decodeExecTransaction: TransactionDecoder = async (
  transaction,
  nonce,
  provider,
  iface
) => {
  const decodedData = iface.decodeFunctionData('execTransaction', transaction.data)
  const signatures = decodedData.signatures
    .slice(2)
    .match(/.{1,130}/g)
    .map((sig: string) => `0x${sig}`)

  const contract = new Contract(transaction.to!, iface, provider)

  const signers = await Promise.all(
    signatures.map(async (sig: string) => {
      const [dataHash] = await contract.functions.getTransactionHash(
        decodedData.to,
        decodedData.value,
        decodedData.data,
        decodedData.operation,
        decodedData.safeTxGas,
        decodedData.baseGas,
        decodedData.gasPrice,
        decodedData.gasToken,
        decodedData.refundReceiver,
        nonce
      )

      return recoverAddress(dataHash, sig)
    })
  )

  return signers
}

const decodeMultiSend: TransactionDecoder = async (transaction, nonce, provider, iface) => {
  const decodedData = iface.decodeFunctionData('multiSend', transaction.data)
  const innerTransactions = parseMultiSendTransactions(decodedData.transactions)
  const signers = await Promise.all(
    innerTransactions.map(async (tx: Transaction) =>  getTransactionSigners(tx, nonce, provider))
  )

  return signers.flat()
}
const parseMultiSendTransactions = (transactions: string): Transaction[] => {
  // Each inner transaction is 32 bytes (to) + 32 bytes (value) + 32 bytes (data length) + N bytes (data)
  // But Gnosis MultiSend uses a custom format:
  // [operation:1][to:20][value:32][dataLen:32][data:dataLen]
  // See: https://github.com/safe-global/safe-contracts/blob/main/contracts/libraries/MultiSend.sol

  const txs: Transaction[] = []
  let offset = 0 // skip '0x'

  const hex = transactions.startsWith('0x') ? transactions.slice(2) : transactions

  while (offset < hex.length) {
    // operation (1 byte)
    const operation = parseInt(hex.slice(offset, offset + 2), 16)
    offset += 2

    // to (20 bytes)
    const to = '0x' + hex.slice(offset, offset + 40)
    offset += 40

    // value (32 bytes)
    const value = utils.hexZeroPad('0x' + hex.slice(offset, offset + 64), 32)
    offset += 64

    // data length (32 bytes)
    const dataLen = parseInt(hex.slice(offset, offset + 64), 16)
    offset += 64

    // data (dataLen bytes)
    const data = '0x' + hex.slice(offset, offset + dataLen * 2)
    offset += dataLen * 2
    
    txs.push({
      to,
      value: BigNumber.from(value),
      data,
      operation,
    } as unknown as Transaction)

  }
  return txs
}


// Registry of transaction decoders
// To add support for new transaction types:
// 1. Create a decoder function following the TransactionDecoder type
// 2. Add it to this registry with the function name as the key
const transactionDecoders: Record<string, TransactionDecoder> = {
  execTransaction: decodeExecTransaction,
  multiSend: decodeMultiSend,
}

// Get the function selector from transaction data
const getFunctionSelector = (data: string): string => {
  return data.slice(0, 10) // First 4 bytes (8 hex chars + 0x)
}

// Get function name from selector using the interface
const getFunctionName = (selector: string, iface: utils.Interface): string | null => {
  try {
    const fragment = iface.getFunction(selector)
    return fragment.name
  } catch {
    return null
  }
}

export const getTransactionSigners = async (
  transaction: Transaction,
  nonce: number,
  provider: providers.JsonRpcProvider
): Promise<string[]> => {
  try {
    const iface = new utils.Interface(GnosisSafe)
    const selector = getFunctionSelector(transaction.data)
    const functionName = getFunctionName(selector, iface)

    if (!functionName || !transactionDecoders[functionName]) {
      console.warn(`No decoder available for function: ${functionName || 'unknown'}`)
      return []
    }

    const decoder = transactionDecoders[functionName]
    return await decoder(transaction, nonce, provider, iface)
  } catch (error) {
    console.warn('Failed to decode transaction:', error)
    return []
  }
}

export const getTransactionData = async (
  transaction: any, 
  nonce: number, 
  provider: providers.JsonRpcProvider,
) => {
  const executor = utils.getAddress(transaction.from)
  const signers = await getTransactionSigners(transaction, nonce, provider)
  return { executor, signers, transaction }
}

export const loadPastSigners = async (address: string, provider?: providers.JsonRpcProvider, _chainId?: number) => {
  if (!provider) return

  const logs = await provider.getLogs({
    address,
    fromBlock: 0,
    toBlock: 'latest',
    topics: ['0x9465fa0c962cc76958e6373a993326400c1c94f8be2fe3a952adfa7f60b2ea26'], // AddedOwner
  })

  const signers = logs.map((log) => utils.getAddress(utils.hexDataSlice(log.data, 12)))

  return signers
}

export const loadTransactions = async (address: string, provider?: providers.JsonRpcProvider, _chainId?: number) => {
  if (!provider) return

  const transactions = await pRetry(() => getAddressTransactions(address, provider), { retries: 5 })

  const parsedTransactions = await Promise.all(
    transactions.map(async (tx: any, nonce: number) => getTransactionData(tx, nonce, provider))
  )

  return parsedTransactions
}

const getAddressTransactions = async (
  address: string,
  provider: providers.JsonRpcProvider
): Promise<Array<Transaction>> => {
  const logs = await provider.getLogs({
    address,
    fromBlock: 0,
    toBlock: 'latest',
    topics: ['0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e'], // ExecutionSuccess
  })

  const transactions = await Promise.all(
    logs.map(async (log: any) => {
      const tx = await provider.getTransaction(log.transactionHash)
      return tx
    })
  )

  return transactions
}

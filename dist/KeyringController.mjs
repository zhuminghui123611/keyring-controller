var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _KeyringController_instances, _KeyringController_controllerOperationMutex, _KeyringController_vaultOperationMutex, _KeyringController_keyringBuilders, _KeyringController_encryptor, _KeyringController_cacheEncryptionKey, _KeyringController_keyrings, _KeyringController_unsupportedKeyrings, _KeyringController_password, _KeyringController_qrKeyringStateListener, _KeyringController_registerMessageHandlers, _KeyringController_getKeyringById, _KeyringController_getKeyringByIdOrDefault, _KeyringController_getKeyringMetadata, _KeyringController_getKeyringBuilderForType, _KeyringController_addQRKeyring, _KeyringController_subscribeToQRKeyringEvents, _KeyringController_unsubscribeFromQRKeyringsEvents, _KeyringController_createNewVaultWithKeyring, _KeyringController_verifySeedPhrase, _KeyringController_getUpdatedKeyrings, _KeyringController_getSerializedKeyrings, _KeyringController_getSessionState, _KeyringController_restoreSerializedKeyrings, _KeyringController_unlockKeyrings, _KeyringController_updateVault, _KeyringController_isNewEncryptionAvailable, _KeyringController_getAccountsFromKeyrings, _KeyringController_createKeyringWithFirstAccount, _KeyringController_newKeyring, _KeyringController_createKeyring, _KeyringController_clearKeyrings, _KeyringController_restoreKeyring, _KeyringController_destroyKeyring, _KeyringController_removeEmptyKeyrings, _KeyringController_assertNoDuplicateAccounts, _KeyringController_setUnlocked, _KeyringController_assertIsUnlocked, _KeyringController_persistOrRollback, _KeyringController_withRollback, _KeyringController_assertControllerMutexIsLocked, _KeyringController_withControllerLock, _KeyringController_withVaultLock;
function $importDefault(module) {
    if (module?.__esModule) {
        return module.default;
    }
    return module;
}
import { isValidPrivate, getBinarySize } from "@ethereumjs/util";
import { BaseController } from "@metamask/base-controller";
import * as encryptorUtils from "@metamask/browser-passworder";
import { HdKeyring } from "@metamask/eth-hd-keyring";
import { normalize as ethNormalize } from "@metamask/eth-sig-util";
import SimpleKeyring from "@metamask/eth-simple-keyring";
import { add0x, assertIsStrictHexString, bytesToHex, hasProperty, hexToBytes, isObject, isStrictHexString, isValidHexAddress, isValidJson, remove0x } from "@metamask/utils";
import { Mutex } from "async-mutex";
import $Wallet from "ethereumjs-wallet";
const { thirdparty: importers } = $Wallet;
const Wallet = $importDefault($Wallet);
import $lodash from "lodash";
const { isEqual } = $lodash;
// When generating a ULID within the same millisecond, monotonicFactory provides some guarantees regarding sort order.
import { ulid } from "ulid";
import { KeyringControllerError } from "./constants.mjs";
const name = 'KeyringController';
/**
 * Available keyring types
 */
export var KeyringTypes;
(function (KeyringTypes) {
    KeyringTypes["simple"] = "Simple Key Pair";
    KeyringTypes["hd"] = "HD Key Tree";
    KeyringTypes["qr"] = "QR Hardware Wallet Device";
    KeyringTypes["trezor"] = "Trezor Hardware";
    KeyringTypes["oneKey"] = "OneKey Hardware";
    KeyringTypes["ledger"] = "Ledger Hardware";
    KeyringTypes["lattice"] = "Lattice Hardware";
    KeyringTypes["snap"] = "Snap Keyring";
})(KeyringTypes || (KeyringTypes = {}));
/**
 * Custody keyring types are a special case, as they are not a single type
 * but they all start with the prefix "Custody".
 *
 * @param keyringType - The type of the keyring.
 * @returns Whether the keyring type is a custody keyring.
 */
export const isCustodyKeyring = (keyringType) => {
    return keyringType.startsWith('Custody');
};
/**
 * A strategy for importing an account
 */
export var AccountImportStrategy;
(function (AccountImportStrategy) {
    AccountImportStrategy["privateKey"] = "privateKey";
    AccountImportStrategy["json"] = "json";
})(AccountImportStrategy || (AccountImportStrategy = {}));
/**
 * The `signTypedMessage` version
 *
 * @see https://docs.metamask.io/guide/signing-data.html
 */
export var SignTypedDataVersion;
(function (SignTypedDataVersion) {
    SignTypedDataVersion["V1"] = "V1";
    SignTypedDataVersion["V3"] = "V3";
    SignTypedDataVersion["V4"] = "V4";
})(SignTypedDataVersion || (SignTypedDataVersion = {}));
/**
 * Get builder function for `Keyring`
 *
 * Returns a builder function for `Keyring` with a `type` property.
 *
 * @param KeyringConstructor - The Keyring class for the builder.
 * @returns A builder function for the given Keyring.
 */
export function keyringBuilderFactory(KeyringConstructor) {
    const builder = () => new KeyringConstructor();
    builder.type = KeyringConstructor.type;
    return builder;
}
const defaultKeyringBuilders = [
    // todo: keyring types are mismatched, this should be fixed in they keyrings themselves
    // @ts-expect-error keyring types are mismatched
    keyringBuilderFactory(SimpleKeyring),
    // @ts-expect-error keyring types are mismatched
    keyringBuilderFactory(HdKeyring),
];
export const getDefaultKeyringState = () => {
    return {
        isUnlocked: false,
        keyrings: [],
    };
};
/**
 * Assert that the given keyring has an exportable
 * mnemonic.
 *
 * @param keyring - The keyring to check
 * @throws When the keyring does not have a mnemonic
 */
function assertHasUint8ArrayMnemonic(keyring) {
    if (!(hasProperty(keyring, 'mnemonic') && keyring.mnemonic instanceof Uint8Array)) {
        throw new Error("Can't get mnemonic bytes from keyring");
    }
}
/**
 * Assert that the provided encryptor supports
 * encryption and encryption key export.
 *
 * @param encryptor - The encryptor to check.
 * @throws If the encryptor does not support key encryption.
 */
function assertIsExportableKeyEncryptor(encryptor) {
    if (!('importKey' in encryptor &&
        typeof encryptor.importKey === 'function' &&
        'decryptWithKey' in encryptor &&
        typeof encryptor.decryptWithKey === 'function' &&
        'encryptWithKey' in encryptor &&
        typeof encryptor.encryptWithKey === 'function')) {
        throw new Error(KeyringControllerError.UnsupportedEncryptionKeyExport);
    }
}
/**
 * Assert that the provided password is a valid non-empty string.
 *
 * @param password - The password to check.
 * @throws If the password is not a valid string.
 */
function assertIsValidPassword(password) {
    if (typeof password !== 'string') {
        throw new Error(KeyringControllerError.WrongPasswordType);
    }
    if (!password || !password.length) {
        throw new Error(KeyringControllerError.InvalidEmptyPassword);
    }
}
/**
 * Assert that the provided encryption key is a valid non-empty string.
 *
 * @param encryptionKey - The encryption key to check.
 * @throws If the encryption key is not a valid string.
 */
function assertIsEncryptionKeySet(encryptionKey) {
    if (!encryptionKey) {
        throw new Error(KeyringControllerError.EncryptionKeyNotSet);
    }
}
/**
 * Checks if the provided value is a serialized keyrings array.
 *
 * @param array - The value to check.
 * @returns True if the value is a serialized keyrings array.
 */
function isSerializedKeyringsArray(array) {
    return (typeof array === 'object' &&
        Array.isArray(array) &&
        array.every((value) => value.type && isValidJson(value.data)));
}
/**
 * Display For Keyring
 *
 * Is used for adding the current keyrings to the state object.
 *
 * @param keyringWithMetadata - The keyring and its metadata.
 * @param keyringWithMetadata.keyring - The keyring to display.
 * @param keyringWithMetadata.metadata - The metadata of the keyring.
 * @returns A keyring display object, with type and accounts properties.
 */
async function displayForKeyring({ keyring, metadata, }) {
    const accounts = await keyring.getAccounts();
    return {
        type: keyring.type,
        // Cast to `string[]` here is safe here because `accounts` has no nullish
        // values, and `normalize` returns `string` unless given a nullish value
        accounts: accounts.map(normalize),
        metadata,
    };
}
/**
 * Check if address is an ethereum address
 *
 * @param address - An address.
 * @returns Returns true if the address is an ethereum one, false otherwise.
 */
function isEthAddress(address) {
    // We first check if it's a matching `Hex` string, so that is narrows down
    // `address` as an `Hex` type, allowing us to use `isValidHexAddress`
    return (
    // NOTE: This function only checks for lowercased strings
    isStrictHexString(address.toLowerCase()) &&
        // This checks for lowercased addresses and checksum addresses too
        isValidHexAddress(address));
}
/**
 * Normalize ethereum or non-EVM address.
 *
 * @param address - Ethereum or non-EVM address.
 * @returns The normalized address.
 */
function normalize(address) {
    // Since the `KeyringController` is only dealing with address, we have
    // no other way to get the associated account type with this address. So we
    // are down to check the actual address format for now
    // TODO: Find a better way to not have those runtime checks based on the
    //       address value!
    return isEthAddress(address) ? ethNormalize(address) : address;
}
/**
 * Controller responsible for establishing and managing user identity.
 *
 * This class is a wrapper around the `eth-keyring-controller` package. The
 * `eth-keyring-controller` manages the "vault", which is an encrypted store of private keys, and
 * it manages the wallet "lock" state. This wrapper class has convenience methods for interacting
 * with the internal keyring controller and handling certain complex operations that involve the
 * keyrings.
 */
export class KeyringController extends BaseController {
    /**
     * Creates a KeyringController instance.
     *
     * @param options - Initial options used to configure this controller
     * @param options.encryptor - An optional object for defining encryption schemes.
     * @param options.keyringBuilders - Set a new name for account.
     * @param options.cacheEncryptionKey - Whether to cache or not encryption key.
     * @param options.messenger - A restricted messenger.
     * @param options.state - Initial state to set on this controller.
     */
    constructor(options) {
        const { encryptor = encryptorUtils, keyringBuilders, messenger, state, } = options;
        super({
            name,
            metadata: {
                vault: { persist: true, anonymous: false },
                isUnlocked: { persist: false, anonymous: true },
                keyrings: { persist: false, anonymous: false },
                encryptionKey: { persist: false, anonymous: false },
                encryptionSalt: { persist: false, anonymous: false },
            },
            messenger,
            state: {
                ...getDefaultKeyringState(),
                ...state,
            },
        });
        _KeyringController_instances.add(this);
        _KeyringController_controllerOperationMutex.set(this, new Mutex());
        _KeyringController_vaultOperationMutex.set(this, new Mutex());
        _KeyringController_keyringBuilders.set(this, void 0);
        _KeyringController_encryptor.set(this, void 0);
        _KeyringController_cacheEncryptionKey.set(this, void 0);
        _KeyringController_keyrings.set(this, void 0);
        _KeyringController_unsupportedKeyrings.set(this, void 0);
        _KeyringController_password.set(this, void 0);
        _KeyringController_qrKeyringStateListener.set(this, void 0);
        __classPrivateFieldSet(this, _KeyringController_keyringBuilders, keyringBuilders
            ? keyringBuilders.concat(defaultKeyringBuilders)
            : defaultKeyringBuilders, "f");
        __classPrivateFieldSet(this, _KeyringController_encryptor, encryptor, "f");
        __classPrivateFieldSet(this, _KeyringController_keyrings, [], "f");
        __classPrivateFieldSet(this, _KeyringController_unsupportedKeyrings, [], "f");
        // This option allows the controller to cache an exported key
        // for use in decrypting and encrypting data without password
        __classPrivateFieldSet(this, _KeyringController_cacheEncryptionKey, Boolean(options.cacheEncryptionKey), "f");
        if (__classPrivateFieldGet(this, _KeyringController_cacheEncryptionKey, "f")) {
            assertIsExportableKeyEncryptor(encryptor);
        }
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_registerMessageHandlers).call(this);
    }
    /**
     * Adds a new account to the default (first) HD seed phrase keyring.
     *
     * @param accountCount - Number of accounts before adding a new one, used to
     * make the method idempotent.
     * @returns Promise resolving to the added account address.
     */
    async addNewAccount(accountCount) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            const primaryKeyring = this.getKeyringsByType('HD Key Tree')[0];
            if (!primaryKeyring) {
                throw new Error('No HD keyring found');
            }
            const oldAccounts = await primaryKeyring.getAccounts();
            if (accountCount && oldAccounts.length !== accountCount) {
                if (accountCount > oldAccounts.length) {
                    throw new Error('Account out of sequence');
                }
                // we return the account already existing at index `accountCount`
                const existingAccount = oldAccounts[accountCount];
                if (!existingAccount) {
                    throw new Error(`Can't find account at index ${accountCount}`);
                }
                return existingAccount;
            }
            const [addedAccountAddress] = await primaryKeyring.addAccounts(1);
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_verifySeedPhrase).call(this);
            return addedAccountAddress;
        });
    }
    /**
     * Adds a new account to the specified keyring.
     *
     * @param keyring - Keyring to add the account to.
     * @param accountCount - Number of accounts before adding a new one, used to make the method idempotent.
     * @returns Promise resolving to the added account address
     */
    async addNewAccountForKeyring(keyring, accountCount) {
        // READ THIS CAREFULLY:
        // We still uses `Hex` here, since we are not using this method when creating
        // and account using a "Snap Keyring". This function assume the `keyring` is
        // ethereum compatible, but "Snap Keyring" might not be.
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            const oldAccounts = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getAccountsFromKeyrings).call(this);
            if (accountCount && oldAccounts.length !== accountCount) {
                if (accountCount > oldAccounts.length) {
                    throw new Error('Account out of sequence');
                }
                const existingAccount = oldAccounts[accountCount];
                assertIsStrictHexString(existingAccount);
                return existingAccount;
            }
            await keyring.addAccounts(1);
            const addedAccountAddress = (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getAccountsFromKeyrings).call(this)).find((selectedAddress) => !oldAccounts.includes(selectedAddress));
            assertIsStrictHexString(addedAccountAddress);
            return addedAccountAddress;
        });
    }
    /**
     * Effectively the same as creating a new keychain then populating it
     * using the given seed phrase.
     *
     * @param password - Password to unlock keychain.
     * @param seed - A BIP39-compliant seed phrase as Uint8Array,
     * either as a string or an array of UTF-8 bytes that represent the string.
     * @returns Promise resolving when the operation ends successfully.
     */
    async createNewVaultAndRestore(password, seed) {
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            assertIsValidPassword(password);
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_createNewVaultWithKeyring).call(this, password, {
                type: KeyringTypes.hd,
                opts: {
                    mnemonic: seed,
                    numberOfAccounts: 1,
                },
            });
        });
    }
    /**
     * Create a new vault and primary keyring.
     *
     * This only works if keyrings are empty. If there is a pre-existing unlocked vault, calling this will have no effect.
     * If there is a pre-existing locked vault, it will be replaced.
     *
     * @param password - Password to unlock the new vault.
     * @returns Promise resolving when the operation ends successfully.
     */
    async createNewVaultAndKeychain(password) {
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            const accounts = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getAccountsFromKeyrings).call(this);
            if (!accounts.length) {
                await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_createNewVaultWithKeyring).call(this, password, {
                    type: KeyringTypes.hd,
                });
            }
        });
    }
    /**
     * Adds a new keyring of the given `type`.
     *
     * @param type - Keyring type name.
     * @param opts - Keyring options.
     * @throws If a builder for the given `type` does not exist.
     * @returns Promise resolving to the new keyring metadata.
     */
    async addNewKeyring(type, opts) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        if (type === KeyringTypes.qr) {
            return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringMetadata).call(this, await this.getOrAddQRKeyring());
        }
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringMetadata).call(this, await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, type, opts)));
    }
    /**
     * Method to verify a given password validity. Throws an
     * error if the password is invalid.
     *
     * @param password - Password of the keyring.
     */
    async verifyPassword(password) {
        if (!this.state.vault) {
            throw new Error(KeyringControllerError.VaultError);
        }
        await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").decrypt(password, this.state.vault);
    }
    /**
     * Returns the status of the vault.
     *
     * @returns Boolean returning true if the vault is unlocked.
     */
    isUnlocked() {
        return this.state.isUnlocked;
    }
    /**
     * Gets the seed phrase of the HD keyring.
     *
     * @param password - Password of the keyring.
     * @param keyringId - The id of the keyring.
     * @returns Promise resolving to the seed phrase.
     */
    async exportSeedPhrase(password, keyringId) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        await this.verifyPassword(password);
        const selectedKeyring = __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringByIdOrDefault).call(this, keyringId);
        if (!selectedKeyring) {
            throw new Error('Keyring not found');
        }
        assertHasUint8ArrayMnemonic(selectedKeyring);
        return selectedKeyring.mnemonic;
    }
    /**
     * Gets the private key from the keyring controlling an address.
     *
     * @param password - Password of the keyring.
     * @param address - Address to export.
     * @returns Promise resolving to the private key for an address.
     */
    async exportAccount(password, address) {
        await this.verifyPassword(password);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.exportAccount) {
            throw new Error(KeyringControllerError.UnsupportedExportAccount);
        }
        return await keyring.exportAccount(normalize(address));
    }
    /**
     * Returns the public addresses of all accounts from every keyring.
     *
     * @returns A promise resolving to an array of addresses.
     */
    async getAccounts() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return this.state.keyrings.reduce((accounts, keyring) => accounts.concat(keyring.accounts), []);
    }
    /**
     * Get encryption public key.
     *
     * @param account - An account address.
     * @param opts - Additional encryption options.
     * @throws If the `account` does not exist or does not support the `getEncryptionPublicKey` method
     * @returns Promise resolving to encyption public key of the `account` if one exists.
     */
    async getEncryptionPublicKey(account, opts) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = ethNormalize(account);
        const keyring = (await this.getKeyringForAccount(account));
        if (!keyring.getEncryptionPublicKey) {
            throw new Error(KeyringControllerError.UnsupportedGetEncryptionPublicKey);
        }
        return await keyring.getEncryptionPublicKey(address, opts);
    }
    /**
     * Attempts to decrypt the provided message parameters.
     *
     * @param messageParams - The decryption message parameters.
     * @param messageParams.from - The address of the account you want to use to decrypt the message.
     * @param messageParams.data - The encrypted data that you want to decrypt.
     * @returns The raw decryption result.
     */
    async decryptMessage(messageParams) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = ethNormalize(messageParams.from);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.decryptMessage) {
            throw new Error(KeyringControllerError.UnsupportedDecryptMessage);
        }
        return keyring.decryptMessage(address, messageParams.data);
    }
    /**
     * Returns the currently initialized keyring that manages
     * the specified `address` if one exists.
     *
     * @deprecated Use of this method is discouraged as actions executed directly on
     * keyrings are not being reflected in the KeyringController state and not
     * persisted in the vault. Use `withKeyring` instead.
     * @param account - An account address.
     * @returns Promise resolving to keyring of the `account` if one exists.
     */
    async getKeyringForAccount(account) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = normalize(account);
        const candidates = await Promise.all(__classPrivateFieldGet(this, _KeyringController_keyrings, "f").map(async ({ keyring }) => {
            return Promise.all([keyring, keyring.getAccounts()]);
        }));
        const winners = candidates.filter((candidate) => {
            const accounts = candidate[1].map(normalize);
            return accounts.includes(address);
        });
        if (winners.length && winners[0]?.length) {
            return winners[0][0];
        }
        // Adding more info to the error
        let errorInfo = '';
        if (!candidates.length) {
            errorInfo = 'There are no keyrings';
        }
        else if (!winners.length) {
            errorInfo = 'There are keyrings, but none match the address';
        }
        throw new Error(`${KeyringControllerError.NoKeyring}. Error info: ${errorInfo}`);
    }
    /**
     * Returns all keyrings of the given type.
     *
     * @deprecated Use of this method is discouraged as actions executed directly on
     * keyrings are not being reflected in the KeyringController state and not
     * persisted in the vault. Use `withKeyring` instead.
     * @param type - Keyring type name.
     * @returns An array of keyrings of the given type.
     */
    getKeyringsByType(type) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_keyrings, "f")
            .filter(({ keyring }) => keyring.type === type)
            .map(({ keyring }) => keyring);
    }
    /**
     * Persist all serialized keyrings in the vault.
     *
     * @deprecated This method is being phased out in favor of `withKeyring`.
     * @returns Promise resolving with `true` value when the
     * operation completes.
     */
    async persistAllKeyrings() {
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withRollback).call(this, async () => {
            __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_updateVault).call(this);
            return true;
        });
    }
    /**
     * Imports an account with the specified import strategy.
     *
     * @param strategy - Import strategy name.
     * @param args - Array of arguments to pass to the underlying stategy.
     * @throws Will throw when passed an unrecognized strategy.
     * @returns Promise resolving to the imported account address.
     */
    async importAccountWithStrategy(strategy, 
    // TODO: Replace `any` with type
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    args) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            let privateKey;
            switch (strategy) {
                case AccountImportStrategy.privateKey:
                    const [importedKey] = args;
                    if (!importedKey) {
                        throw new Error('Cannot import an empty key.');
                    }
                    const prefixed = add0x(importedKey);
                    let bufferedPrivateKey;
                    try {
                        bufferedPrivateKey = hexToBytes(prefixed);
                    }
                    catch {
                        throw new Error('Cannot import invalid private key.');
                    }
                    if (!isValidPrivate(bufferedPrivateKey) ||
                        // ensures that the key is 64 bytes long
                        getBinarySize(prefixed) !== 64 + '0x'.length) {
                        throw new Error('Cannot import invalid private key.');
                    }
                    privateKey = remove0x(prefixed);
                    break;
                case AccountImportStrategy.json:
                    let wallet;
                    const [input, password] = args;
                    try {
                        wallet = importers.fromEtherWallet(input, password);
                    }
                    catch (e) {
                        wallet = wallet || (await Wallet.fromV3(input, password, true));
                    }
                    privateKey = bytesToHex(wallet.getPrivateKey());
                    break;
                default:
                    throw new Error(`Unexpected import strategy: '${String(strategy)}'`);
            }
            const newKeyring = (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, KeyringTypes.simple, [
                privateKey,
            ]));
            const accounts = await newKeyring.getAccounts();
            return accounts[0];
        });
    }
    /**
     * Removes an account from keyring state.
     *
     * @param address - Address of the account to remove.
     * @fires KeyringController:accountRemoved
     * @returns Promise resolving when the account is removed.
     */
    async removeAccount(address) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            const keyring = (await this.getKeyringForAccount(address));
            const keyringIndex = this.state.keyrings.findIndex((kr) => kr.accounts.includes(address));
            const isPrimaryKeyring = keyringIndex === 0;
            const shouldRemoveKeyring = (await keyring.getAccounts()).length === 1;
            // Primary keyring should never be removed, so we need to keep at least one account in it
            if (isPrimaryKeyring && shouldRemoveKeyring) {
                throw new Error(KeyringControllerError.LastAccountInPrimaryKeyring);
            }
            // Not all the keyrings support this, so we have to check
            if (!keyring.removeAccount) {
                throw new Error(KeyringControllerError.UnsupportedRemoveAccount);
            }
            // The `removeAccount` method of snaps keyring is async. We have to update
            // the interface of the other keyrings to be async as well.
            // FIXME: We do cast to `Hex` to makes the type checker happy here, and
            // because `Keyring<State>.removeAccount` requires address to be `Hex`. Those
            // type would need to be updated for a full non-EVM support.
            keyring.removeAccount(address);
            if (shouldRemoveKeyring) {
                await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_removeEmptyKeyrings).call(this);
            }
        });
        this.messagingSystem.publish(`${name}:accountRemoved`, address);
    }
    /**
     * Deallocates all secrets and locks the wallet.
     *
     * @returns Promise resolving when the operation completes.
     */
    async setLocked() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withRollback).call(this, async () => {
            __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_unsubscribeFromQRKeyringsEvents).call(this);
            __classPrivateFieldSet(this, _KeyringController_password, undefined, "f");
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_clearKeyrings).call(this);
            this.update((state) => {
                state.isUnlocked = false;
                state.keyrings = [];
                delete state.encryptionKey;
                delete state.encryptionSalt;
            });
            this.messagingSystem.publish(`${name}:lock`);
        });
    }
    /**
     * Signs message by calling down into a specific keyring.
     *
     * @param messageParams - PersonalMessageParams object to sign.
     * @returns Promise resolving to a signed message string.
     */
    async signMessage(messageParams) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        if (!messageParams.data) {
            throw new Error("Can't sign an empty message");
        }
        const address = ethNormalize(messageParams.from);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.signMessage) {
            throw new Error(KeyringControllerError.UnsupportedSignMessage);
        }
        return await keyring.signMessage(address, messageParams.data);
    }
    /**
     * Signs EIP-7702 Authorization message by calling down into a specific keyring.
     *
     * @param params - EIP7702AuthorizationParams object to sign.
     * @returns Promise resolving to an EIP-7702 Authorization signature.
     * @throws Will throw UnsupportedSignEIP7702Authorization if the keyring does not support signing EIP-7702 Authorization messages.
     */
    async signEip7702Authorization(params) {
        const from = ethNormalize(params.from);
        const keyring = (await this.getKeyringForAccount(from));
        if (!keyring.signEip7702Authorization) {
            throw new Error(KeyringControllerError.UnsupportedSignEip7702Authorization);
        }
        const { chainId, nonce } = params;
        const contractAddress = ethNormalize(params.contractAddress);
        if (contractAddress === undefined) {
            throw new Error(KeyringControllerError.MissingEip7702AuthorizationContractAddress);
        }
        return await keyring.signEip7702Authorization(from, [
            chainId,
            contractAddress,
            nonce,
        ]);
    }
    /**
     * Signs personal message by calling down into a specific keyring.
     *
     * @param messageParams - PersonalMessageParams object to sign.
     * @returns Promise resolving to a signed message string.
     */
    async signPersonalMessage(messageParams) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = ethNormalize(messageParams.from);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.signPersonalMessage) {
            throw new Error(KeyringControllerError.UnsupportedSignPersonalMessage);
        }
        const normalizedData = normalize(messageParams.data);
        return await keyring.signPersonalMessage(address, normalizedData);
    }
    /**
     * Signs typed message by calling down into a specific keyring.
     *
     * @param messageParams - TypedMessageParams object to sign.
     * @param version - Compatibility version EIP712.
     * @throws Will throw when passed an unrecognized version.
     * @returns Promise resolving to a signed message string or an error if any.
     */
    async signTypedMessage(messageParams, version) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        try {
            if (![
                SignTypedDataVersion.V1,
                SignTypedDataVersion.V3,
                SignTypedDataVersion.V4,
            ].includes(version)) {
                throw new Error(`Unexpected signTypedMessage version: '${version}'`);
            }
            // Cast to `Hex` here is safe here because `messageParams.from` is not nullish.
            // `normalize` returns `Hex` unless given a nullish value.
            const address = ethNormalize(messageParams.from);
            const keyring = (await this.getKeyringForAccount(address));
            if (!keyring.signTypedData) {
                throw new Error(KeyringControllerError.UnsupportedSignTypedMessage);
            }
            return await keyring.signTypedData(address, version !== SignTypedDataVersion.V1 &&
                typeof messageParams.data === 'string'
                ? JSON.parse(messageParams.data)
                : messageParams.data, { version });
        }
        catch (error) {
            // TODO: Either fix this lint violation or explain why it's necessary to ignore.
            // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
            throw new Error(`Keyring Controller signTypedMessage: ${error}`);
        }
    }
    /**
     * Signs a transaction by calling down into a specific keyring.
     *
     * @param transaction - Transaction object to sign. Must be a `ethereumjs-tx` transaction instance.
     * @param from - Address to sign from, should be in keychain.
     * @param opts - An optional options object.
     * @returns Promise resolving to a signed transaction string.
     */
    async signTransaction(transaction, from, opts) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = ethNormalize(from);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.signTransaction) {
            throw new Error(KeyringControllerError.UnsupportedSignTransaction);
        }
        return await keyring.signTransaction(address, transaction, opts);
    }
    /**
     * Convert a base transaction to a base UserOperation.
     *
     * @param from - Address of the sender.
     * @param transactions - Base transactions to include in the UserOperation.
     * @param executionContext - The execution context to use for the UserOperation.
     * @returns A pseudo-UserOperation that can be used to construct a real.
     */
    async prepareUserOperation(from, transactions, executionContext) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = ethNormalize(from);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.prepareUserOperation) {
            throw new Error(KeyringControllerError.UnsupportedPrepareUserOperation);
        }
        return await keyring.prepareUserOperation(address, transactions, executionContext);
    }
    /**
     * Patches properties of a UserOperation. Currently, only the
     * `paymasterAndData` can be patched.
     *
     * @param from - Address of the sender.
     * @param userOp - UserOperation to patch.
     * @param executionContext - The execution context to use for the UserOperation.
     * @returns A patch to apply to the UserOperation.
     */
    async patchUserOperation(from, userOp, executionContext) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = ethNormalize(from);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.patchUserOperation) {
            throw new Error(KeyringControllerError.UnsupportedPatchUserOperation);
        }
        return await keyring.patchUserOperation(address, userOp, executionContext);
    }
    /**
     * Signs an UserOperation.
     *
     * @param from - Address of the sender.
     * @param userOp - UserOperation to sign.
     * @param executionContext - The execution context to use for the UserOperation.
     * @returns The signature of the UserOperation.
     */
    async signUserOperation(from, userOp, executionContext) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const address = ethNormalize(from);
        const keyring = (await this.getKeyringForAccount(address));
        if (!keyring.signUserOperation) {
            throw new Error(KeyringControllerError.UnsupportedSignUserOperation);
        }
        return await keyring.signUserOperation(address, userOp, executionContext);
    }
    /**
     * Changes the password used to encrypt the vault.
     *
     * @param password - The new password.
     * @returns Promise resolving when the operation completes.
     */
    changePassword(password) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        // If the password is the same, do nothing.
        if (__classPrivateFieldGet(this, _KeyringController_password, "f") === password) {
            return Promise.resolve();
        }
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            assertIsValidPassword(password);
            __classPrivateFieldSet(this, _KeyringController_password, password, "f");
            // We need to clear encryption key and salt from state
            // to force the controller to re-encrypt the vault using
            // the new password.
            if (__classPrivateFieldGet(this, _KeyringController_cacheEncryptionKey, "f")) {
                this.update((state) => {
                    delete state.encryptionKey;
                    delete state.encryptionSalt;
                });
            }
        });
    }
    /**
     * Attempts to decrypt the current vault and load its keyrings, using the
     * given encryption key and salt. The optional salt can be used to check for
     * consistency with the vault salt.
     *
     * @param encryptionKey - Key to unlock the keychain.
     * @param encryptionSalt - Optional salt to unlock the keychain.
     * @returns Promise resolving when the operation completes.
     */
    async submitEncryptionKey(encryptionKey, encryptionSalt) {
        const { newMetadata } = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withRollback).call(this, async () => {
            const result = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_unlockKeyrings).call(this, undefined, encryptionKey, encryptionSalt);
            __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_setUnlocked).call(this);
            return result;
        });
        try {
            // if new metadata has been generated during login, we
            // can attempt to upgrade the vault.
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withRollback).call(this, async () => {
                if (newMetadata) {
                    await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_updateVault).call(this);
                }
            });
        }
        catch (error) {
            // We don't want to throw an error if the upgrade fails
            // since the controller is already unlocked.
            console.error('Failed to update vault during login:', error);
        }
    }
    /**
     * Exports the vault encryption key.
     *
     * @returns The vault encryption key.
     */
    async exportEncryptionKey() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withControllerLock).call(this, async () => {
            const { encryptionKey } = this.state;
            assertIsEncryptionKeySet(encryptionKey);
            return encryptionKey;
        });
    }
    /**
     * Attempts to decrypt the current vault and load its keyrings,
     * using the given password.
     *
     * @param password - Password to unlock the keychain.
     * @returns Promise resolving when the operation completes.
     */
    async submitPassword(password) {
        const { newMetadata } = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withRollback).call(this, async () => {
            const result = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_unlockKeyrings).call(this, password);
            __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_setUnlocked).call(this);
            return result;
        });
        try {
            // If there are stronger encryption params available, or
            // if new metadata has been generated during login, we
            // can attempt to upgrade the vault.
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withRollback).call(this, async () => {
                if (newMetadata || __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_isNewEncryptionAvailable).call(this)) {
                    await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_updateVault).call(this);
                }
            });
        }
        catch (error) {
            // We don't want to throw an error if the upgrade fails
            // since the controller is already unlocked.
            console.error('Failed to update vault during login:', error);
        }
    }
    /**
     * Verifies the that the seed phrase restores the current keychain's accounts.
     *
     * @param keyringId - The id of the keyring to verify.
     * @returns Promise resolving to the seed phrase as Uint8Array.
     */
    async verifySeedPhrase(keyringId) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withControllerLock).call(this, async () => __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_verifySeedPhrase).call(this, keyringId));
    }
    async withKeyring(selector, operation, options = {
        createIfMissing: false,
    }) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            let keyring;
            if ('address' in selector) {
                keyring = (await this.getKeyringForAccount(selector.address));
            }
            else if ('type' in selector) {
                keyring = this.getKeyringsByType(selector.type)[selector.index || 0];
                if (!keyring && options.createIfMissing) {
                    keyring = (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, selector.type, options.createWithData));
                }
            }
            else if ('id' in selector) {
                keyring = __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringById).call(this, selector.id);
            }
            if (!keyring) {
                throw new Error(KeyringControllerError.KeyringNotFound);
            }
            const result = await operation({
                keyring,
                metadata: __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringMetadata).call(this, keyring),
            });
            if (Object.is(result, keyring)) {
                // Access to a keyring instance outside of controller safeguards
                // should be discouraged, as it can lead to unexpected behavior.
                // This error is thrown to prevent consumers using `withKeyring`
                // as a way to get a reference to a keyring instance.
                throw new Error(KeyringControllerError.UnsafeDirectKeyringAccess);
            }
            return result;
        });
    }
    // QR Hardware related methods
    /**
     * Get QR Hardware keyring.
     *
     * @returns The QR Keyring if defined, otherwise undefined
     * @deprecated Use `withKeyring` instead.
     */
    getQRKeyring() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        // QRKeyring is not yet compatible with Keyring type from @metamask/utils
        return this.getKeyringsByType(KeyringTypes.qr)[0];
    }
    /**
     * Get QR hardware keyring. If it doesn't exist, add it.
     *
     * @returns The added keyring
     * @deprecated Use `addNewKeyring` and `withKeyring` instead.
     */
    async getOrAddQRKeyring() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return (this.getQRKeyring() ||
            (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_addQRKeyring).call(this))));
    }
    /**
     * Restore QR keyring from serialized data.
     *
     * @param serialized - Serialized data to restore the keyring from.
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    // TODO: Replace `any` with type
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async restoreQRKeyring(serialized) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            const keyring = this.getQRKeyring() || (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_addQRKeyring).call(this));
            keyring.deserialize(serialized);
        });
    }
    /**
     * Reset QR keyring state.
     *
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    async resetQRKeyringState() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        (await this.getOrAddQRKeyring()).resetStore();
    }
    /**
     * Get QR keyring state.
     *
     * @returns Promise resolving to the keyring state.
     * @deprecated Use `withKeyring` or subscribe to `"KeyringController:qrKeyringStateChange"`
     * instead.
     */
    async getQRKeyringState() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return (await this.getOrAddQRKeyring()).getMemStore();
    }
    /**
     * Submit QR hardware wallet public HDKey.
     *
     * @param cryptoHDKey - The key to submit.
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    async submitQRCryptoHDKey(cryptoHDKey) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        (await this.getOrAddQRKeyring()).submitCryptoHDKey(cryptoHDKey);
    }
    /**
     * Submit QR hardware wallet account.
     *
     * @param cryptoAccount - The account to submit.
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    async submitQRCryptoAccount(cryptoAccount) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        (await this.getOrAddQRKeyring()).submitCryptoAccount(cryptoAccount);
    }
    /**
     * Submit QR hardware wallet signature.
     *
     * @param requestId - The request ID.
     * @param ethSignature - The signature to submit.
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    async submitQRSignature(requestId, ethSignature) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        (await this.getOrAddQRKeyring()).submitSignature(requestId, ethSignature);
    }
    /**
     * Cancel QR sign request.
     *
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    async cancelQRSignRequest() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        (await this.getOrAddQRKeyring()).cancelSignRequest();
    }
    /**
     * Cancels qr keyring sync.
     *
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    async cancelQRSynchronization() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        (await this.getOrAddQRKeyring()).cancelSync();
    }
    /**
     * Connect to QR hardware wallet.
     *
     * @param page - The page to connect to.
     * @returns Promise resolving to the connected accounts.
     * @deprecated Use of this method is discouraged as it creates a dangling promise
     * internal to the `QRKeyring`, which can lead to unpredictable deadlocks. Please use
     * `withKeyring` instead.
     */
    async connectQRHardware(page) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            try {
                const keyring = this.getQRKeyring() || (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_addQRKeyring).call(this));
                let accounts;
                switch (page) {
                    case -1:
                        accounts = await keyring.getPreviousPage();
                        break;
                    case 1:
                        accounts = await keyring.getNextPage();
                        break;
                    default:
                        accounts = await keyring.getFirstPage();
                }
                // TODO: Replace `any` with type
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                return accounts.map((account) => {
                    return {
                        ...account,
                        balance: '0x0',
                    };
                });
            }
            catch (e) {
                // TODO: Add test case for when keyring throws
                /* istanbul ignore next */
                // TODO: Either fix this lint violation or explain why it's necessary to ignore.
                // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
                throw new Error(`Unspecified error when connect QR Hardware, ${e}`);
            }
        });
    }
    /**
     * Unlock a QR hardware wallet account.
     *
     * @param index - The index of the account to unlock.
     * @returns Promise resolving when the operation completes.
     * @deprecated Use `withKeyring` instead.
     */
    async unlockQRHardwareWalletAccount(index) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            const keyring = this.getQRKeyring() || (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_addQRKeyring).call(this));
            keyring.setAccountToUnlock(index);
            await keyring.addAccounts(1);
        });
    }
    async getAccountKeyringType(account) {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        const keyring = (await this.getKeyringForAccount(account));
        return keyring.type;
    }
    /**
     * Forget the QR hardware wallet.
     *
     * @returns Promise resolving to the removed accounts and the remaining accounts.
     * @deprecated Use `withKeyring` instead.
     */
    async forgetQRDevice() {
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertIsUnlocked).call(this);
        return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_persistOrRollback).call(this, async () => {
            const keyring = this.getQRKeyring();
            if (!keyring) {
                return { removedAccounts: [], remainingAccounts: [] };
            }
            const allAccounts = (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getAccountsFromKeyrings).call(this));
            keyring.forgetDevice();
            const remainingAccounts = (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getAccountsFromKeyrings).call(this));
            const removedAccounts = allAccounts.filter((address) => !remainingAccounts.includes(address));
            return { removedAccounts, remainingAccounts };
        });
    }
}
_KeyringController_controllerOperationMutex = new WeakMap(), _KeyringController_vaultOperationMutex = new WeakMap(), _KeyringController_keyringBuilders = new WeakMap(), _KeyringController_encryptor = new WeakMap(), _KeyringController_cacheEncryptionKey = new WeakMap(), _KeyringController_keyrings = new WeakMap(), _KeyringController_unsupportedKeyrings = new WeakMap(), _KeyringController_password = new WeakMap(), _KeyringController_qrKeyringStateListener = new WeakMap(), _KeyringController_instances = new WeakSet(), _KeyringController_registerMessageHandlers = function _KeyringController_registerMessageHandlers() {
    this.messagingSystem.registerActionHandler(`${name}:signMessage`, this.signMessage.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:signEip7702Authorization`, this.signEip7702Authorization.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:signPersonalMessage`, this.signPersonalMessage.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:signTypedMessage`, this.signTypedMessage.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:decryptMessage`, this.decryptMessage.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:getEncryptionPublicKey`, this.getEncryptionPublicKey.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:getAccounts`, this.getAccounts.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:getKeyringsByType`, this.getKeyringsByType.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:getKeyringForAccount`, this.getKeyringForAccount.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:persistAllKeyrings`, this.persistAllKeyrings.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:prepareUserOperation`, this.prepareUserOperation.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:patchUserOperation`, this.patchUserOperation.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:signUserOperation`, this.signUserOperation.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:addNewAccount`, this.addNewAccount.bind(this));
    this.messagingSystem.registerActionHandler(`${name}:withKeyring`, this.withKeyring.bind(this));
}, _KeyringController_getKeyringById = function _KeyringController_getKeyringById(keyringId) {
    return __classPrivateFieldGet(this, _KeyringController_keyrings, "f").find(({ metadata }) => metadata.id === keyringId)
        ?.keyring;
}, _KeyringController_getKeyringByIdOrDefault = function _KeyringController_getKeyringByIdOrDefault(keyringId) {
    if (!keyringId) {
        return __classPrivateFieldGet(this, _KeyringController_keyrings, "f")[0]?.keyring;
    }
    return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringById).call(this, keyringId);
}, _KeyringController_getKeyringMetadata = function _KeyringController_getKeyringMetadata(keyring) {
    const keyringWithMetadata = __classPrivateFieldGet(this, _KeyringController_keyrings, "f").find((candidate) => candidate.keyring === keyring);
    if (!keyringWithMetadata) {
        throw new Error(KeyringControllerError.KeyringNotFound);
    }
    return keyringWithMetadata.metadata;
}, _KeyringController_getKeyringBuilderForType = function _KeyringController_getKeyringBuilderForType(type) {
    return __classPrivateFieldGet(this, _KeyringController_keyringBuilders, "f").find((keyringBuilder) => keyringBuilder.type === type);
}, _KeyringController_addQRKeyring = 
/**
 * Add qr hardware keyring.
 *
 * @returns The added keyring
 * @throws If a QRKeyring builder is not provided
 * when initializing the controller
 */
async function _KeyringController_addQRKeyring() {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    // QRKeyring is not yet compatible with Keyring type from @metamask/utils
    return (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, KeyringTypes.qr));
}, _KeyringController_subscribeToQRKeyringEvents = function _KeyringController_subscribeToQRKeyringEvents(qrKeyring) {
    __classPrivateFieldSet(this, _KeyringController_qrKeyringStateListener, (state) => {
        this.messagingSystem.publish(`${name}:qrKeyringStateChange`, state);
    }, "f");
    qrKeyring.getMemStore().subscribe(__classPrivateFieldGet(this, _KeyringController_qrKeyringStateListener, "f"));
}, _KeyringController_unsubscribeFromQRKeyringsEvents = function _KeyringController_unsubscribeFromQRKeyringsEvents() {
    const qrKeyrings = this.getKeyringsByType(KeyringTypes.qr);
    qrKeyrings.forEach((qrKeyring) => {
        if (__classPrivateFieldGet(this, _KeyringController_qrKeyringStateListener, "f")) {
            qrKeyring.getMemStore().unsubscribe(__classPrivateFieldGet(this, _KeyringController_qrKeyringStateListener, "f"));
        }
    });
}, _KeyringController_createNewVaultWithKeyring = 
/**
 * Create new vault with an initial keyring
 *
 * Destroys any old encrypted storage,
 * creates a new encrypted store with the given password,
 * creates a new wallet with 1 account.
 *
 * @fires KeyringController:unlock
 * @param password - The password to encrypt the vault with.
 * @param keyring - A object containing the params to instantiate a new keyring.
 * @param keyring.type - The keyring type.
 * @param keyring.opts - Optional parameters required to instantiate the keyring.
 * @returns A promise that resolves to the state.
 */
async function _KeyringController_createNewVaultWithKeyring(password, keyring) {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    if (typeof password !== 'string') {
        throw new TypeError(KeyringControllerError.WrongPasswordType);
    }
    this.update((state) => {
        delete state.encryptionKey;
        delete state.encryptionSalt;
    });
    __classPrivateFieldSet(this, _KeyringController_password, password, "f");
    await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_clearKeyrings).call(this);
    await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_createKeyringWithFirstAccount).call(this, keyring.type, keyring.opts);
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_setUnlocked).call(this);
}, _KeyringController_verifySeedPhrase = 
/**
 * Internal non-exclusive method to verify the seed phrase.
 *
 * @param keyringId - The id of the keyring to verify the seed phrase for.
 * @returns A promise resolving to the seed phrase as Uint8Array.
 */
async function _KeyringController_verifySeedPhrase(keyringId) {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    const keyring = __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringByIdOrDefault).call(this, keyringId);
    if (!keyring) {
        throw new Error(KeyringControllerError.KeyringNotFound);
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
    if (keyring.type !== KeyringTypes.hd) {
        throw new Error(KeyringControllerError.UnsupportedVerifySeedPhrase);
    }
    assertHasUint8ArrayMnemonic(keyring);
    const seedWords = keyring.mnemonic;
    const accounts = await keyring.getAccounts();
    /* istanbul ignore if */
    if (accounts.length === 0) {
        throw new Error('Cannot verify an empty keyring.');
    }
    // The HD Keyring Builder is a default keyring builder
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const hdKeyringBuilder = __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringBuilderForType).call(this, KeyringTypes.hd);
    const hdKeyring = hdKeyringBuilder();
    // @ts-expect-error @metamask/eth-hd-keyring correctly handles
    // Uint8Array seed phrases in the `deserialize` method.
    await hdKeyring.deserialize({
        mnemonic: seedWords,
        numberOfAccounts: accounts.length,
    });
    const testAccounts = await hdKeyring.getAccounts();
    /* istanbul ignore if */
    if (testAccounts.length !== accounts.length) {
        throw new Error('Seed phrase imported incorrect number of accounts.');
    }
    testAccounts.forEach((account, i) => {
        /* istanbul ignore if */
        if (account.toLowerCase() !== accounts[i].toLowerCase()) {
            throw new Error('Seed phrase imported different accounts.');
        }
    });
    return seedWords;
}, _KeyringController_getUpdatedKeyrings = 
/**
 * Get the updated array of each keyring's type and
 * accounts list.
 *
 * @returns A promise resolving to the updated keyrings array.
 */
async function _KeyringController_getUpdatedKeyrings() {
    return Promise.all(__classPrivateFieldGet(this, _KeyringController_keyrings, "f").map(displayForKeyring));
}, _KeyringController_getSerializedKeyrings = 
/**
 * Serialize the current array of keyring instances,
 * including unsupported keyrings by default.
 *
 * @param options - Method options.
 * @param options.includeUnsupported - Whether to include unsupported keyrings.
 * @returns The serialized keyrings.
 */
async function _KeyringController_getSerializedKeyrings({ includeUnsupported } = {
    includeUnsupported: true,
}) {
    const serializedKeyrings = await Promise.all(__classPrivateFieldGet(this, _KeyringController_keyrings, "f").map(async ({ keyring, metadata }) => {
        return {
            type: keyring.type,
            data: await keyring.serialize(),
            metadata,
        };
    }));
    if (includeUnsupported) {
        serializedKeyrings.push(...__classPrivateFieldGet(this, _KeyringController_unsupportedKeyrings, "f"));
    }
    return serializedKeyrings;
}, _KeyringController_getSessionState = 
/**
 * Get a snapshot of session data held by class variables.
 *
 * @returns An object with serialized keyrings, keyrings metadata,
 * and the user password.
 */
async function _KeyringController_getSessionState() {
    return {
        keyrings: await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getSerializedKeyrings).call(this),
        password: __classPrivateFieldGet(this, _KeyringController_password, "f"),
    };
}, _KeyringController_restoreSerializedKeyrings = 
/**
 * Restore a serialized keyrings array.
 *
 * @param serializedKeyrings - The serialized keyrings array.
 * @returns The restored keyrings.
 */
async function _KeyringController_restoreSerializedKeyrings(serializedKeyrings) {
    await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_clearKeyrings).call(this);
    const keyrings = [];
    let newMetadata = false;
    for (const serializedKeyring of serializedKeyrings) {
        const result = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_restoreKeyring).call(this, serializedKeyring);
        if (result) {
            const { keyring, metadata } = result;
            keyrings.push({ keyring, metadata });
            if (result.newMetadata) {
                newMetadata = true;
            }
        }
    }
    return { keyrings, newMetadata };
}, _KeyringController_unlockKeyrings = 
/**
 * Unlock Keyrings, decrypting the vault and deserializing all
 * keyrings contained in it, using a password or an encryption key with salt.
 *
 * @param password - The keyring controller password.
 * @param encryptionKey - An exported key string to unlock keyrings with.
 * @param encryptionSalt - The salt used to encrypt the vault.
 * @returns A promise resolving to the deserialized keyrings array.
 */
async function _KeyringController_unlockKeyrings(password, encryptionKey, encryptionSalt) {
    return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withVaultLock).call(this, async () => {
        const encryptedVault = this.state.vault;
        if (!encryptedVault) {
            throw new Error(KeyringControllerError.VaultError);
        }
        let vault;
        const updatedState = {};
        if (__classPrivateFieldGet(this, _KeyringController_cacheEncryptionKey, "f")) {
            assertIsExportableKeyEncryptor(__classPrivateFieldGet(this, _KeyringController_encryptor, "f"));
            if (password) {
                const result = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").decryptWithDetail(password, encryptedVault);
                vault = result.vault;
                __classPrivateFieldSet(this, _KeyringController_password, password, "f");
                updatedState.encryptionKey = result.exportedKeyString;
                updatedState.encryptionSalt = result.salt;
            }
            else {
                const parsedEncryptedVault = JSON.parse(encryptedVault);
                if (encryptionSalt && encryptionSalt !== parsedEncryptedVault.salt) {
                    throw new Error(KeyringControllerError.ExpiredCredentials);
                }
                else {
                    encryptionSalt = parsedEncryptedVault.salt;
                }
                if (typeof encryptionKey !== 'string') {
                    throw new TypeError(KeyringControllerError.WrongPasswordType);
                }
                const key = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").importKey(encryptionKey);
                vault = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").decryptWithKey(key, parsedEncryptedVault);
                // This call is required on the first call because encryptionKey
                // is not yet inside the memStore
                updatedState.encryptionKey = encryptionKey;
                updatedState.encryptionSalt = encryptionSalt;
            }
        }
        else {
            if (typeof password !== 'string') {
                throw new TypeError(KeyringControllerError.WrongPasswordType);
            }
            vault = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").decrypt(password, encryptedVault);
            __classPrivateFieldSet(this, _KeyringController_password, password, "f");
        }
        if (!isSerializedKeyringsArray(vault)) {
            throw new Error(KeyringControllerError.VaultDataError);
        }
        const { keyrings, newMetadata } = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_restoreSerializedKeyrings).call(this, vault);
        const updatedKeyrings = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getUpdatedKeyrings).call(this);
        this.update((state) => {
            state.keyrings = updatedKeyrings;
            if (updatedState.encryptionKey || updatedState.encryptionSalt) {
                state.encryptionKey = updatedState.encryptionKey;
                state.encryptionSalt = updatedState.encryptionSalt;
            }
        });
        return { keyrings, newMetadata };
    });
}, _KeyringController_updateVault = function _KeyringController_updateVault() {
    return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withVaultLock).call(this, async () => {
        // Ensure no duplicate accounts are persisted.
        await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertNoDuplicateAccounts).call(this);
        const { encryptionKey, encryptionSalt, vault } = this.state;
        // READ THIS CAREFULLY:
        // We do check if the vault is still considered up-to-date, if not, we would not re-use the
        // cached key and we will re-generate a new one (based on the password).
        //
        // This helps doing seamless updates of the vault. Useful in case we change some cryptographic
        // parameters to the KDF.
        const useCachedKey = encryptionKey && vault && __classPrivateFieldGet(this, _KeyringController_encryptor, "f").isVaultUpdated?.(vault);
        if (!__classPrivateFieldGet(this, _KeyringController_password, "f") && !encryptionKey) {
            throw new Error(KeyringControllerError.MissingCredentials);
        }
        const serializedKeyrings = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getSerializedKeyrings).call(this);
        if (!serializedKeyrings.some((keyring) => keyring.type === KeyringTypes.hd)) {
            throw new Error(KeyringControllerError.NoHdKeyring);
        }
        const updatedState = {};
        if (__classPrivateFieldGet(this, _KeyringController_cacheEncryptionKey, "f")) {
            assertIsExportableKeyEncryptor(__classPrivateFieldGet(this, _KeyringController_encryptor, "f"));
            if (useCachedKey) {
                const key = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").importKey(encryptionKey);
                const vaultJSON = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").encryptWithKey(key, serializedKeyrings);
                vaultJSON.salt = encryptionSalt;
                updatedState.vault = JSON.stringify(vaultJSON);
            }
            else if (__classPrivateFieldGet(this, _KeyringController_password, "f")) {
                const { vault: newVault, exportedKeyString } = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").encryptWithDetail(__classPrivateFieldGet(this, _KeyringController_password, "f"), serializedKeyrings);
                updatedState.vault = newVault;
                updatedState.encryptionKey = exportedKeyString;
            }
        }
        else {
            assertIsValidPassword(__classPrivateFieldGet(this, _KeyringController_password, "f"));
            updatedState.vault = await __classPrivateFieldGet(this, _KeyringController_encryptor, "f").encrypt(__classPrivateFieldGet(this, _KeyringController_password, "f"), serializedKeyrings);
        }
        if (!updatedState.vault) {
            throw new Error(KeyringControllerError.MissingVaultData);
        }
        const updatedKeyrings = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getUpdatedKeyrings).call(this);
        this.update((state) => {
            state.vault = updatedState.vault;
            state.keyrings = updatedKeyrings;
            if (updatedState.encryptionKey) {
                state.encryptionKey = updatedState.encryptionKey;
                state.encryptionSalt = JSON.parse(updatedState.vault).salt;
            }
        });
        return true;
    });
}, _KeyringController_isNewEncryptionAvailable = function _KeyringController_isNewEncryptionAvailable() {
    const { vault } = this.state;
    if (!vault || !__classPrivateFieldGet(this, _KeyringController_password, "f") || !__classPrivateFieldGet(this, _KeyringController_encryptor, "f").isVaultUpdated) {
        return false;
    }
    return !__classPrivateFieldGet(this, _KeyringController_encryptor, "f").isVaultUpdated(vault);
}, _KeyringController_getAccountsFromKeyrings = 
/**
 * Retrieves all the accounts from keyrings instances
 * that are currently in memory.
 *
 * @param additionalKeyrings - Additional keyrings to include in the search.
 * @returns A promise resolving to an array of accounts.
 */
async function _KeyringController_getAccountsFromKeyrings(additionalKeyrings = []) {
    const keyrings = __classPrivateFieldGet(this, _KeyringController_keyrings, "f").map(({ keyring }) => keyring);
    const keyringArrays = await Promise.all([...keyrings, ...additionalKeyrings].map(async (keyring) => keyring.getAccounts()));
    const addresses = keyringArrays.reduce((res, arr) => {
        return res.concat(arr);
    }, []);
    // Cast to `string[]` here is safe here because `addresses` has no nullish
    // values, and `normalize` returns `string` unless given a nullish value
    return addresses.map(normalize);
}, _KeyringController_createKeyringWithFirstAccount = 
/**
 * Create a new keyring, ensuring that the first account is
 * also created.
 *
 * @param type - Keyring type to instantiate.
 * @param opts - Optional parameters required to instantiate the keyring.
 * @returns A promise that resolves if the operation is successful.
 */
async function _KeyringController_createKeyringWithFirstAccount(type, opts) {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    const keyring = (await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, type, opts));
    const [firstAccount] = await keyring.getAccounts();
    if (!firstAccount) {
        throw new Error(KeyringControllerError.NoFirstAccount);
    }
    return firstAccount;
}, _KeyringController_newKeyring = 
/**
 * Instantiate, initialize and return a new keyring of the given `type`,
 * using the given `opts`. The keyring is built using the keyring builder
 * registered for the given `type`.
 *
 * The internal keyring and keyring metadata arrays are updated with the new
 * keyring as well.
 *
 * @param type - The type of keyring to add.
 * @param data - Keyring initialization options.
 * @returns The new keyring.
 * @throws If the keyring includes duplicated accounts.
 */
async function _KeyringController_newKeyring(type, data) {
    const keyring = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_createKeyring).call(this, type, data);
    __classPrivateFieldGet(this, _KeyringController_keyrings, "f").push({ keyring, metadata: getDefaultKeyringMetadata() });
    return keyring;
}, _KeyringController_createKeyring = 
/**
 * Instantiate, initialize and return a keyring of the given `type` using the
 * given `opts`. The keyring is built using the keyring builder registered
 * for the given `type`.
 *
 * The keyring might be new, or it might be restored from the vault. This
 * function should only be called from `#newKeyring` or `#restoreKeyring`,
 * for the "new" and "restore" cases respectively.
 *
 * The internal keyring and keyring metadata arrays are *not* updated, the
 * caller is expected to update them.
 *
 * @param type - The type of keyring to add.
 * @param data - Keyring initialization options.
 * @returns The new keyring.
 * @throws If the keyring includes duplicated accounts.
 */
async function _KeyringController_createKeyring(type, data) {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    const keyringBuilder = __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getKeyringBuilderForType).call(this, type);
    if (!keyringBuilder) {
        throw new Error(`${KeyringControllerError.NoKeyringBuilder}. Keyring type: ${type}`);
    }
    const keyring = keyringBuilder();
    if (data) {
        // @ts-expect-error Enforce data type after updating clients
        await keyring.deserialize(data);
    }
    if (keyring.init) {
        await keyring.init();
    }
    if (type === KeyringTypes.hd && (!isObject(data) || !data.mnemonic)) {
        if (!keyring.generateRandomMnemonic) {
            throw new Error(KeyringControllerError.UnsupportedGenerateRandomMnemonic);
        }
        // NOTE: Not all keyrings implement this method in a asynchronous-way. Using `await` for
        // non-thenable will still be valid (despite not being really useful). It allows us to cover both
        // cases and allow retro-compatibility too.
        await keyring.generateRandomMnemonic();
        await keyring.addAccounts(1);
    }
    if (type === KeyringTypes.qr) {
        // In case of a QR keyring type, we need to subscribe
        // to its events after creating it
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_subscribeToQRKeyringEvents).call(this, keyring);
    }
    return keyring;
}, _KeyringController_clearKeyrings = 
/**
 * Remove all managed keyrings, destroying all their
 * instances in memory.
 */
async function _KeyringController_clearKeyrings() {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    for (const { keyring } of __classPrivateFieldGet(this, _KeyringController_keyrings, "f")) {
        await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_destroyKeyring).call(this, keyring);
    }
    __classPrivateFieldSet(this, _KeyringController_keyrings, [], "f");
    __classPrivateFieldSet(this, _KeyringController_unsupportedKeyrings, [], "f");
}, _KeyringController_restoreKeyring = 
/**
 * Restore a Keyring from a provided serialized payload.
 * On success, returns the resulting keyring instance.
 *
 * @param serialized - The serialized keyring.
 * @returns The deserialized keyring or undefined if the keyring type is unsupported.
 */
async function _KeyringController_restoreKeyring(serialized) {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    try {
        const { type, data, metadata: serializedMetadata } = serialized;
        let newMetadata = false;
        let metadata = serializedMetadata;
        const keyring = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_createKeyring).call(this, type, data);
        await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertNoDuplicateAccounts).call(this, [keyring]);
        // If metadata is missing, assume the data is from an installation before
        // we had keyring metadata.
        if (!metadata) {
            newMetadata = true;
            metadata = getDefaultKeyringMetadata();
        }
        // The keyring is added to the keyrings array only if it's successfully restored
        // and the metadata is successfully added to the controller
        __classPrivateFieldGet(this, _KeyringController_keyrings, "f").push({
            keyring,
            metadata,
        });
        return { keyring, metadata, newMetadata };
    }
    catch (error) {
        console.error(error);
        __classPrivateFieldGet(this, _KeyringController_unsupportedKeyrings, "f").push(serialized);
        return undefined;
    }
}, _KeyringController_destroyKeyring = 
/**
 * Destroy Keyring
 *
 * Some keyrings support a method called `destroy`, that destroys the
 * keyring along with removing all its event listeners and, in some cases,
 * clears the keyring bridge iframe from the DOM.
 *
 * @param keyring - The keyring to destroy.
 */
async function _KeyringController_destroyKeyring(keyring) {
    await keyring.destroy?.();
}, _KeyringController_removeEmptyKeyrings = 
/**
 * Remove empty keyrings.
 *
 * Loops through the keyrings and removes the ones with empty accounts
 * (usually after removing the last / only account) from a keyring.
 */
async function _KeyringController_removeEmptyKeyrings() {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    const validKeyrings = [];
    // Since getAccounts returns a Promise
    // We need to wait to hear back form each keyring
    // in order to decide which ones are now valid (accounts.length > 0)
    await Promise.all(__classPrivateFieldGet(this, _KeyringController_keyrings, "f").map(async ({ keyring, metadata }) => {
        const accounts = await keyring.getAccounts();
        if (accounts.length > 0) {
            validKeyrings.push({ keyring, metadata });
        }
        else {
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_destroyKeyring).call(this, keyring);
        }
    }));
    __classPrivateFieldSet(this, _KeyringController_keyrings, validKeyrings, "f");
}, _KeyringController_assertNoDuplicateAccounts = 
/**
 * Assert that there are no duplicate accounts in the keyrings.
 *
 * @param additionalKeyrings - Additional keyrings to include in the check.
 * @throws If there are duplicate accounts.
 */
async function _KeyringController_assertNoDuplicateAccounts(additionalKeyrings = []) {
    const accounts = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getAccountsFromKeyrings).call(this, additionalKeyrings);
    if (new Set(accounts).size !== accounts.length) {
        throw new Error(KeyringControllerError.DuplicatedAccount);
    }
}, _KeyringController_setUnlocked = function _KeyringController_setUnlocked() {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    this.update((state) => {
        state.isUnlocked = true;
    });
    this.messagingSystem.publish(`${name}:unlock`);
}, _KeyringController_assertIsUnlocked = function _KeyringController_assertIsUnlocked() {
    if (!this.state.isUnlocked) {
        throw new Error(KeyringControllerError.ControllerLocked);
    }
}, _KeyringController_persistOrRollback = 
/**
 * Execute the given function after acquiring the controller lock
 * and save the vault to state after it (only if needed), or rollback to their
 * previous state in case of error.
 *
 * @param callback - The function to execute.
 * @returns The result of the function.
 */
async function _KeyringController_persistOrRollback(callback) {
    return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withRollback).call(this, async ({ releaseLock }) => {
        const oldState = JSON.stringify(await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getSessionState).call(this));
        const callbackResult = await callback({ releaseLock });
        const newState = JSON.stringify(await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getSessionState).call(this));
        // State is committed only if the operation is successful and need to trigger a vault update.
        if (!isEqual(oldState, newState)) {
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_updateVault).call(this);
        }
        return callbackResult;
    });
}, _KeyringController_withRollback = 
/**
 * Execute the given function after acquiring the controller lock
 * and rollback keyrings and password states in case of error.
 *
 * @param callback - The function to execute atomically.
 * @returns The result of the function.
 */
async function _KeyringController_withRollback(callback) {
    return __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_withControllerLock).call(this, async ({ releaseLock }) => {
        const currentSerializedKeyrings = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_getSerializedKeyrings).call(this);
        const currentPassword = __classPrivateFieldGet(this, _KeyringController_password, "f");
        try {
            return await callback({ releaseLock });
        }
        catch (e) {
            // Keyrings and password are restored to their previous state
            __classPrivateFieldSet(this, _KeyringController_password, currentPassword, "f");
            await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_restoreSerializedKeyrings).call(this, currentSerializedKeyrings);
            throw e;
        }
    });
}, _KeyringController_assertControllerMutexIsLocked = function _KeyringController_assertControllerMutexIsLocked() {
    if (!__classPrivateFieldGet(this, _KeyringController_controllerOperationMutex, "f").isLocked()) {
        throw new Error(KeyringControllerError.ControllerLockRequired);
    }
}, _KeyringController_withControllerLock = 
/**
 * Lock the controller mutex before executing the given function,
 * and release it after the function is resolved or after an
 * error is thrown.
 *
 * This wrapper ensures that each mutable operation that interacts with the
 * controller and that changes its state is executed in a mutually exclusive way,
 * preventing unsafe concurrent access that could lead to unpredictable behavior.
 *
 * @param callback - The function to execute while the controller mutex is locked.
 * @returns The result of the function.
 */
async function _KeyringController_withControllerLock(callback) {
    return withLock(__classPrivateFieldGet(this, _KeyringController_controllerOperationMutex, "f"), callback);
}, _KeyringController_withVaultLock = 
/**
 * Lock the vault mutex before executing the given function,
 * and release it after the function is resolved or after an
 * error is thrown.
 *
 * This ensures that each operation that interacts with the vault
 * is executed in a mutually exclusive way.
 *
 * @param callback - The function to execute while the vault mutex is locked.
 * @returns The result of the function.
 */
async function _KeyringController_withVaultLock(callback) {
    __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_assertControllerMutexIsLocked).call(this);
    return withLock(__classPrivateFieldGet(this, _KeyringController_vaultOperationMutex, "f"), callback);
};
/**
 * Lock the given mutex before executing the given function,
 * and release it after the function is resolved or after an
 * error is thrown.
 *
 * @param mutex - The mutex to lock.
 * @param callback - The function to execute while the mutex is locked.
 * @returns The result of the function.
 */
async function withLock(mutex, callback) {
    const releaseLock = await mutex.acquire();
    try {
        return await callback({ releaseLock });
    }
    finally {
        releaseLock();
    }
}
/**
 * Generate a new keyring metadata object.
 *
 * @returns Keyring metadata.
 */
function getDefaultKeyringMetadata() {
    return { id: ulid(), name: '' };
}
export default KeyringController;
//# sourceMappingURL=KeyringController.mjs.map
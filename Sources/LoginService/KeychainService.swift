import Security
import Foundation
import Combine


// MARK: - keychain service
public struct KeychainService<Account: IAccount> {
    public var saveAccount: (Account) throws -> ()
    
    public var getAccounts: () throws -> [Account]

    public var removeAccount: (Account) throws -> ()
    
    public var removeAccounts: () throws -> ()
    
    public var login: (Account) -> ()
    
    public var logout: () -> ()
    
    public var getCurrentAccount: ([Account]) throws -> Account?
}


public extension KeychainService {
    static func live(_ service: String) -> Self {
        func saveAccount(_ account: Account) throws {
            guard
                let idData = account.identifier.data(using: .utf8),
                let accountData = try? JSONEncoder().encode(account)
            else {
                throw LoginError.keychainReadFailed
            }

            // Create a keychain query dictionary
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                
                kSecAttrAccount as String: idData,
                kSecValueData as String: accountData,
            ]

            // Delete any existing credentials for the same account before saving
            SecItemDelete(query as CFDictionary)

            // Add the new credentials to the Keychain
            let status = SecItemAdd(query as CFDictionary, nil)
            if status != errSecSuccess {
                throw LoginError.keychainSaveFailed
            }
        }
        
        func getAccounts() throws -> [Account] {
            var accounts: [Account] = []

            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,

                kSecReturnAttributes as String: true, //kCFBooleanTrue
                kSecReturnData as String: true, //kCFBooleanTrue
                kSecMatchLimit as String: kSecMatchLimitAll
            ]

            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)

            if status == errSecSuccess, let items = result as? [[String: Any]] {
                for item in items {
                    guard  let accountData = item[kSecValueData as String]     as? Data else { continue}
                    
                    if let account = try? JSONDecoder().decode(Account.self, from: accountData) {
                        accounts.append(account)
                    }else {
                        throw LoginError.encodeFailed
                    }
                }
            }
            
            return accounts
        }

        func removeAccount(_ account: Account) throws {
            guard
                let idData = account.identifier.data(using: .utf8)
            else {
                throw LoginError.keychainReadFailed
            }
            
            let delete: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                
                kSecAttrAccount as String: idData
            ]

            let status = SecItemDelete(delete as CFDictionary)
            if(status != errSecSuccess){
                throw LoginError.keychainStatus(status)
            }
        }
        
        func removeAccounts() throws {
            let delete: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword
            ]
            let status = SecItemDelete(delete as CFDictionary)
            if(status != errSecSuccess){
                throw LoginError.keychainStatus(status)
            }
        }
        
        func login(_ account: Account){
            UserDefaults.standard.set(account.identifier, forKey: "currentAccount")
        }
        
        func logout(){
            UserDefaults.standard.removeObject(forKey: "currentAccount")
        }
        
        func getCurrentAccount(_ accounts: [Account]) throws -> Account? {
            let currentAccount = UserDefaults.standard.string(forKey: "currentAccount")
            
            if(currentAccount == nil){
                return nil
            }
            
            if let current = accounts.first(where: {
                $0.identifier == currentAccount
            }) {
                return current
            }else{
                throw LoginError.keychainReadFailed
            }
            
        }
        
        return Self(
            saveAccount: saveAccount,
            getAccounts: getAccounts,
            removeAccount: removeAccount,
            removeAccounts: removeAccounts,
            login: login,
            logout: logout,
            getCurrentAccount: getCurrentAccount
        )
    }
    
    static var mock: Self {
        var current: Account?
        var accounts: [Account] = []
        
        return Self(
            saveAccount: { a in
                if let index = accounts.firstIndex(where: {$0.identifier == a.identifier}) {
                    accounts[index] = a
                } else {
                    accounts.append(a)
                }
            },
            getAccounts: { accounts },
            removeAccount: { a in accounts.removeAll(where: { $0.identifier == a.identifier}) },
            removeAccounts: { accounts.removeAll() },
            login: { current = $0 },
            logout: { current = nil },
            getCurrentAccount: { _ in current }
        )
    }
}

import Security
import Foundation
import Combine

// MARK: - keychain service
@available(iOS 16.0, *)
public class KeychainService<Account: IAccount> {
    // MARK: - private functions
    private let service: String
    
    public init(_ service: String){
        self.service = service
    }
    
    public func saveAccount(_ account: Account) throws {
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
    
    public func getAccounts() throws -> [Account] {
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
        }else {
            throw LoginError.encodeFailed
        }
        
        return accounts
    }

    public func removeAccounts() throws -> [Account] {
        let delete: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword
        ]
        let status = SecItemDelete(delete as CFDictionary)
        if(status != errSecSuccess){
            throw LoginError.keychainStatus(status)
        }
        return []
    }
    
    public func login(_ account: Account){
        UserDefaults.standard.set(account.identifier, forKey: "currentAccount")
    }
    
    public func logout(){
        UserDefaults.standard.removeObject(forKey: "currentAccount")
    }
    
    public func getCurrentAccount(_ accounts: [Account]) throws -> Account? {
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
}







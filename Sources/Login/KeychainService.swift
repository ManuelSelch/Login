import Security
import Foundation
import Combine

public protocol IAccount: Codable {
    var identifier: String {get set}
}

// MARK: - keychain service
@available(iOS 16.0, *)
public class KeychainService<Account: IAccount> {
    // MARK: - private functions
    private let service: String
    
    public init(_ service: String = "de.selch"){
        self.service = service
    }
    
    public func saveAccount(_ account: Account) -> AnyPublisher<Bool, Error> {
        
        guard
            let idData = account.identifier.data(using: .utf8),
            let accountData = try? JSONEncoder().encode(account)
        else {
            return Fail(error: LoginError.keychainReadFailed).eraseToAnyPublisher()
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
            return Fail(error: LoginError.keychainSaveFailed).eraseToAnyPublisher()
        }else{
            return just(true)
        }
    }
    
    public func getAccounts() -> AnyPublisher<[Account], Error> {
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
                }
            }
        }
        
        return Just(accounts)
            .setFailureType(to: Error.self)
            .eraseToAnyPublisher()
    }

    public func removeAccounts() -> AnyPublisher<[Account], Error> {
        let delete: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword
        ]
        _ = SecItemDelete(delete as CFDictionary)
        
        return Just([])
            .setFailureType(to: Error.self)
            .eraseToAnyPublisher()
    }
    
    public func login(_ account: Account){
        UserDefaults.standard.set(account.identifier, forKey: "currentAccount")
    }
    
    public func getCurrentAccount(_ accounts: [Account]) -> AnyPublisher<Account, Error> {
        let currentAccount = UserDefaults.standard.string(forKey: "currentAccount")
        
        if(currentAccount == nil){
            return Empty().eraseToAnyPublisher()
        }
        
        if let current = accounts.first(where: {
            $0.identifier == currentAccount
        }) {
            return just(current)
        }else{
            return Fail(error: LoginError.keychainReadFailed).eraseToAnyPublisher()
        }
        
    }
    
    func just<T>(_ event: T) -> AnyPublisher<T, Error> {
        return Just(event)
            .setFailureType(to: Error.self)
            .eraseToAnyPublisher()
    }

}







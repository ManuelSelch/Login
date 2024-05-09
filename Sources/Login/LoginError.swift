import Foundation

enum LoginError: Error {
    case keychainReadFailed
    case keychainSaveFailed
}

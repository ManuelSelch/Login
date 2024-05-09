import Foundation

public enum LoginError: Error {
    case keychainReadFailed
    case keychainSaveFailed
}

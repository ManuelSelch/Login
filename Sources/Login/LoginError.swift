import Foundation

public enum LoginError: Error {
    case keychainReadFailed
    case keychainSaveFailed
    case encodeFailed
    case keychainStatus(OSStatus)
}

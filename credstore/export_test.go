package credstore

// MasterKeyUser exposes the keyring account name of the master key so
// black-box tests can inspect the keyring entry without duplicating the
// unexported constant.
const MasterKeyUser = masterKeyUser


use bitcoin::bip32::Xpub;
use std::str::FromStr;

pub fn test_xpubs() -> (Xpub, Xpub) {
    (
        Xpub::from_str("tpubDCjgmQsPz1xamjuPHqwFkdU2DfHe9oz4VSgzJD1JDWZWM1pYyk82WMN7zyQRN85F5Yx8Rs2xeGC4eZ5un27LqPu74BDQZcWkqkhnVmbWmMB").unwrap(), // hot Xpub
        Xpub::from_str("tpubDCjgmQsPz1xarEYG4eya8HegHuun3QU5VAJKo8oPwVgMoQb961aP7nv5J9PH9jjj74MzPp1U5YzzjdZF3gFANtMNuMKyrSYKmJt7jQMonM1").unwrap(), // cold Xpub
    )
}


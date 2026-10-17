#
# PKCS15 r/w profile for JCOP cards
#
cardinfo {
    max-pin-length      = 10;
    min-pin-length      = 4;
    pin-encoding        = ascii-numeric;
    pin-pad-char        = 0xFF;
}

pkcs15 {
    # EF(TokenInfo) can only be updated with the SO PIN
    do-last-update      = no;
}

PIN user-pin {
    auth-id   = 03;
    reference = 1;
}

PIN so-pin {
    auth-id   = 04;
    reference = 2;
}

filesystem {
    DF MF {
        DF PKCS15-AppDF {
            acl = *=NONE;
            EF PKCS15-PrKDF {
                file-id         = 4400;
            }
            EF PKCS15-PuKDF {
                file-id         = 4401;
            }
            EF PKCS15-CDF {
                file-id         = 4404;
            }
            EF PKCS15-DODF {
                file-id         = 4407;
            }
            EF PKCS15-AODF {
                file-id         = 4408;
            }
            # Private keys are key objects addressed by key reference,
            # see pkcs15-jcop.c
            EF template-public-key {
                file-id         = 5101;
                structure       = transparent;
                acl             = *=NEVER, READ=NONE, UPDATE=$PIN,
                                  WRITE=$PIN, DELETE=$PIN;
            }
        }
    }
}

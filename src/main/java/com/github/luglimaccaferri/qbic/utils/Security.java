package com.github.luglimaccaferri.qbic.utils;

import at.favre.lib.crypto.bcrypt.BCrypt;

public class Security {
    public static String hashPassword(String password){
        return BCrypt.withDefaults().hashToString(12, password.toCharArray()); // da vedere che fare per i rounds e tutto quanto
    }
}

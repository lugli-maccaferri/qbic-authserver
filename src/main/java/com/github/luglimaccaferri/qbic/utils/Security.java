package com.github.luglimaccaferri.qbic.utils;

import at.favre.lib.crypto.bcrypt.BCrypt;

public class Security {
    public static String hashPassword(String password){
        return BCrypt.withDefaults().hashToString(12, password.toCharArray()); // da vedere che fare per i rounds e tutto quanto
    }
    public static String bytesToHex(byte[] bytes){
        // lenta, ma tanto ci interessa solo una volta ogni tanto
        StringBuilder sb = new StringBuilder();
        for(byte b: bytes){
            sb.append(
                    String.format("%02x", b)
            );
        }

        return sb.toString();
    }
}

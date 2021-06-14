package com.github.luglimaccaferri.qbic.utils;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.luglimaccaferri.qbic.Core;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HashMap;

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

    public static String createJWT(HashMap<String, String> payload){

        Algorithm rsa = Algorithm.RSA256((RSAPublicKey) Core.KEYS.getPublic(), (RSAPrivateKey) Core.KEYS.getPrivate());
        String token = JWT.create()
                .withIssuer("qbic")
                .withClaim("iat", Instant.now().getEpochSecond()) // issued_at
                .withClaim("exp", Instant.now().getEpochSecond() + Core.getConfig().get("jwt_timeout").getAsInt()) // scadenza
                .withPayload(payload)
                .sign(rsa);

        return token;

    }
}

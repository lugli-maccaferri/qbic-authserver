package com.github.luglimaccaferri.qbic.http.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.luglimaccaferri.qbic.Core;
import com.github.luglimaccaferri.qbic.http.models.HTTPError;
import com.github.luglimaccaferri.qbic.http.models.Ok;
import com.github.luglimaccaferri.qbic.data.models.misc.User;
import spark.Route;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HashMap;

public class AuthController {

    public static Route index = (req, res) -> {

        return new Ok().put("message", "/auth endpoint").toResponse(res);

    };

    public static Route login = (req, res) -> {

        String username = req.queryParams("username"),
                password = req.queryParams("password");

        User user = User.from(username);
        HashMap<String, String> payload = new HashMap<String, String>(); // non posso usare Object perché il tipo deve essere conosciuto
        // uso String e poi ri-casto a byte

        if(user == null) return HTTPError.INVALID_CREDENTIALS.toResponse(res);
        if(!user.verifyPassword(password)) return HTTPError.INVALID_CREDENTIALS.toResponse(res);

        payload.put("username", user.getUsername());
        payload.put("user_id", user.getUUID().toString());
        payload.put("is_admin", String.valueOf(user.isAdmin()));
        payload.put("edit_fs", String.valueOf(user.getPermissions().get("edit_fs")));
        payload.put("edit_others", String.valueOf(user.getPermissions().get("edit_others")));

        Algorithm rsa = Algorithm.RSA256((RSAPublicKey) Core.KEYS.getPublic(), (RSAPrivateKey) Core.KEYS.getPrivate());
        String token = JWT.create()
                .withClaim("iat", Instant.now().getEpochSecond()) // issued_at
                .withClaim("exp", Instant.now().getEpochSecond() + Core.getConfig().get("jwt_timeout").getAsInt()) // scadenza
                .withPayload(payload)
                .sign(rsa);

        return new Ok().put("token", token).toResponse(res);

    };

}

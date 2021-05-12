package com.github.luglimaccaferri.qbic.data.models.misc;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.github.jasync.sql.db.QueryResult;
import com.github.jasync.sql.db.ResultSet;
import com.github.jasync.sql.db.RowData;
import com.github.luglimaccaferri.qbic.data.mysql.Connector;
import com.github.luglimaccaferri.qbic.errors.users.ExistingUserException;
import com.github.luglimaccaferri.qbic.utils.Security;

import javax.management.Query;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class User {

    protected final UUID uuid;
    protected String username;
    protected String hash;
    protected final HashMap<String, Boolean> permissions = new HashMap<String, Boolean>();

    public User(UUID uuid){ this.uuid = uuid; }
    private User(String uuid, String username, String password, boolean isAdmin, boolean editFs, boolean editOthers){
        this.uuid = UUID.fromString(uuid);
        this.username = username;
        this.hash = password;
        this.permissions.put("admin", isAdmin);
        this.permissions.put("edit_fs", editFs);
        this.permissions.put("edit_others", editOthers);
    }
    public User fill() throws ExecutionException, InterruptedException {

        CompletableFuture<QueryResult> query = Connector.connection.sendPreparedStatement(
                "SELECT * FROM users WHERE uuid = ?",
                List.of(this.uuid.toString())
        );

        RowData result = query.get().getRows().get(0);

        this.username = String.valueOf(result.get("username"));
        this.hash = String.valueOf(result.get("password"));
        this.permissions.put("admin", "1".equals(result.get("admin")));
        this.permissions.put("edit_fs", "1".equals(result.get("edit_fs")));
        this.permissions.put("edit_others", "1".equals(result.get("edit_others")));

        return this;

    }

    public String getUsername() { return this.username; }
    public String getHash(){ return this.hash; }
    public HashMap<String, Boolean> getPermissions(){ return this.permissions; }
    public UUID getUUID(){ return this.uuid; }
    public boolean isAdmin(){ return this.permissions.get("admin"); }

    public boolean verifyPassword(String password){ return BCrypt.verifyer().verify(password.toCharArray(), this.hash).verified; }

    public static User createInstance(String uuid, String username, String password, boolean isAdmin) throws ExecutionException, InterruptedException, ExistingUserException {
        return User.createInstance(uuid, username, password, isAdmin, true, true);
    }

    public static User createInstance(String uuid, String username, String password, boolean isAdmin, boolean editFs, boolean editOthers) throws ExecutionException, InterruptedException {

        String hashed = Security.hashPassword(password);
        CompletableFuture<QueryResult> query = Connector.connection.sendPreparedStatement(
                "INSERT INTO users VALUES(?, ?, ?, ?, ?, ?)",
                List.of(username, hashed, uuid, editFs, editOthers, isAdmin)
        ); // improbabile collisione di UUID, specialmente in un sistema del genere

        query.get();

        return new User(uuid, username, hashed, isAdmin, editFs, editOthers);

    }


    public static User from(String username) throws ExecutionException, InterruptedException {

        CompletableFuture<QueryResult> query = Connector.connection.sendPreparedStatement(
                "SELECT * FROM users WHERE username = ?",
                List.of(username)
        );
        ResultSet results = query.get().getRows();
        if(results.size() == 0) return null;

        RowData result = results.get(0);

        return new User(
                String.valueOf(
                        result.get("id")
                ),
                String.valueOf(
                        result.get("username")
                ),
                String.valueOf(
                        result.get("password")
                ),
                "1".equals(result.get("admin")),
                "1".equals(result.get("edit_fs")),
                "1".equals(result.get("edit_others"))
        );

    }

}

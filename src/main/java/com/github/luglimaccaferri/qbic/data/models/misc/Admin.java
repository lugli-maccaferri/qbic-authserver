package com.github.luglimaccaferri.qbic.data.models.misc;

import java.util.UUID;

public class Admin extends User{

    public Admin(UUID uuid){ super(uuid); }
    public static Admin from(User user){
        return new Admin(user.getUUID());
    }

}

import mongoose from "mongoose";
import nanoid from "nanoid";
import crypto from 'crypto'
import { encode, decode } from 'base64-arraybuffer';
import User, { IUser, Platform, UserExposedFields , MetadataExposedFields} from "./models/User";
import { getFacebookUser } from "./facebook";

import { MONGO_URI } from "./env";
import { MongoError } from "mongodb";
import FriendRequest, { IFriendRequest } from "./models/FriendRequest";
import { hashPassword, isValidPassword, verifyToken } from "./auth";
import { hooks } from "./hooks";
import Leaderboard, { ILeaderBoard, IPlayer } from "./models/Leaderboard";

const debug = require('debug')('@colyseus/social');
require('source-map-support').install();


const privateKey =`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAw4OPh3+NnpFC78BAvIcvx4mTfJIoNrEiEEHshX45dHN6yPTe
cq9IGg8vXodqkZqfBMx7/sgZK+FvxJkmX8A7PdpRo13O5lFwzIg7UpX4LFn4n8fd
B42iuYaJ5rlmibVaTu74e0NCy6x1QeKMMxprYfWq+Uy3oE+S3vEIZccwSIbGAaK7
NB8TtASJlD+YNQC4jdwRM+PxK9ZMWcdib8zLz5FvuiODnggdpFYZW962B4cZZl35
6tdU5jdGvEURlswHUIsqWWduWhQYnUXgtD4HFOGGtwMjwVtT/6IWnpV/JYtI4GS7
dWzTma8Sa35MrWX9VrpnmBIU+93lc+mbOGg6iQIDAQABAoIBAETyNQA8a+2aHje7
3Vhed+vuyRLp28KFrpR7GvRscchuHMOXDob05wFBj5vPNzaHh0JC9gr/91hxFGAI
/e5QNNP4FEf/AcJYv+VwuTLDbhP92l5GNdy/Br5UAndZtB4l1OX3Aas+KeT3ORZ1
1KkEzQ9redKWSj7/MLTr3OE/X/iC57pQPZsfhuJI7JmVVJaAU1SPaVmyV3TpCt1x
eXldX08CcTdyeRyrOeDBAATub5VPkZ4yDgT9ZHbJ6IT192RfZjpBsLqtw7TdcFG0
/wzUT4C1zP7YGLhH+bALSJFuZ7P459UC60TvOAKPIB5DCYqhhs954Wysb3SbdK6r
7vOUv4ECgYEA+dMBGvp+4gwQQizbo9aBZS2jmDsAczT0Kc9VNakPfnJ5JMl7a1QE
TxY7/ex+mXwSFr/X/E6G7Q5yBk7j/2t/nDP50ZDWHphtvpnep+rmFCeH+DlhWejh
EHGoDVjcS3mPcvjWKrCi8cNcNdNaNLU0wdLgUmjSuBqSIoKiIcee77ECgYEAyFjb
bSrTUGs+UZbM+TYtmgPXasU09iWUDkll8mQwdknyEEcSUR+emf676TwmhEAN7cXi
zWGGJWaxT0hunTygDdM6XtxSz5xrIc6eMD+CPLXtqLbBQ1KX81W9PS6mgJ6QEeBN
4kkqBRYrfJMkv9VrwiIttDXoBPkDQm0OvgYExlkCgYEA0V4w8vc0FyWdCpilim1f
C/hvvkjUW7jpV5DXDJ2eyo4NUPM6Z/yFj/JGXMwyXVdJoZ8t19nH4ivVC8xZ79mb
nMFCgIstp35/mtlBbODD6egnX7RXDg7JcAqQmH78QJSjz+sTMbvPE2ZyhPmYA8xJ
ZpbgQLBwyLIb/qgUUNMHNEECgYEAqBxngyL8Te6vTCcNt9AOU74FdEImPqUppxNP
yCTpxVgnFiGM7SVrICzv4LXoW/Cjv3Dc7xl2Rsv03GIa7zV/2Bn2UMLveeX2v1dw
xWuFDQxbb8ZqRON5PWYkdMJAVIy4t0dQEyDxcXM46j9OBuo+kZe8YgsZtZJ9ea+p
Pyott4ECgYAGDxId00ATm7YmeJQicsZwk197TtM1mx+WrSvRZrjQG8NiyutLQAe2
VDogwY/TkYowBccnx+gNQhkOx6xQOJLD1fxAFQFnX7CzA5pMgoBP7/aEl0QdLoll
+KxsIYyyMCzaiEvZEQoKYSdCiuFXZ6UIiAPGOfmKIC5+UL302dvIhg==
-----END RSA PRIVATE KEY-----\n`;


const publicKey =`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4OPh3+NnpFC78BAvIcv
x4mTfJIoNrEiEEHshX45dHN6yPTecq9IGg8vXodqkZqfBMx7/sgZK+FvxJkmX8A7
PdpRo13O5lFwzIg7UpX4LFn4n8fdB42iuYaJ5rlmibVaTu74e0NCy6x1QeKMMxpr
YfWq+Uy3oE+S3vEIZccwSIbGAaK7NB8TtASJlD+YNQC4jdwRM+PxK9ZMWcdib8zL
z5FvuiODnggdpFYZW962B4cZZl356tdU5jdGvEURlswHUIsqWWduWhQYnUXgtD4H
FOGGtwMjwVtT/6IWnpV/JYtI4GS7dWzTma8Sa35MrWX9VrpnmBIU+93lc+mbOGg6
iQIDAQAB
-----END PUBLIC KEY-----\n`;

const DEFAULT_USER_FIELDS: Array<keyof IUser> = ['_id', 'username', 'displayName', 'avatarUrl', 'metadata'];
const ONLINE_SECONDS = 20;
const LEADER_BOARD_ID = "LeaderBoard1";

let leaderBoardData:ILeaderBoard = null;

export type ObjectId = string | mongoose.Schema.Types.ObjectId;
export type AuthProvider = 'email' | 'facebook' | 'anonymous';

export async function connectDatabase(cb?: (err: MongoError) => void) {
    // skip if already connecting or connected.
    if (mongoose.connection.readyState !== 0) {
        if (cb) cb(null);
        return;
    }

    try {
        await mongoose.connect(MONGO_URI, { autoIndex: false, useNewUrlParser: true, useUnifiedTopology: true }, cb);
        debug(`Successfully connected to ${MONGO_URI}`)

        // reconnect if disconnected.
        mongoose.connection.on('disconnected', () => connectDatabase());
    } catch (e) {
        console.error('Error connecting to database: ', e);
    }
}

function cleanup() {
    try {
        mongoose.disconnect()
        debug(`Successfully Closed connection to  from to ${MONGO_URI}`)
    } catch (e) {
        console.error('Error Closing connection to database: ', e);
    }
}

function createUserName() {
    // Math.random should be unique because of its seeding algorithm.
    // Convert it to base 36 (numbers + letters), and grab the first 9 characters
    // after the decimal.
    return  Math.random().toString(36).substr(2, 9);
};

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

export async function pingUser(userId: ObjectId) {
    return await User.findOne({ _id: userId });
}

export async function authenticate({
    accessToken,
    deviceId,
    platform,
    email,
    password,
    token,
    country
}: {
    accessToken?: string,
    deviceId?: string,
    platform?: string,
    email?: string,
    password?: string,
    token?: string,
    country?: string

}): Promise<IUser> {
    let provider: AuthProvider;

    const $filter: any = {};
    const $set: any = {};
    const $setOnInsert: any = {};

    let friendIds = [];
    let facebookFriendsIds = [];

    const _id = token && verifyToken(token)._id;
    let existingUser: IUser;


    if (accessToken) {
        provider = 'facebook';

        // facebook auth
        const data = await getFacebookUser(accessToken);

        $filter['facebookId'] = data.id;

        $set['facebookId'] = data.id; // upgrading from user token
        $set['avatarUrl'] = data.picture.data.url;
        $set['isAnonymous'] = false;

        if (data.name) {
            $set['displayName'] = data.name;
        }

        if (data.email) {
            $setOnInsert['email'] = data.email;
        }

        if (data.friends) {
            facebookFriendsIds = data.friends.data.map(friend => friend.id);
        }

        // fetch existing users by their facebookId from database
        if (facebookFriendsIds.length > 0) {
            friendIds = (await User.
                find({ facebookId: { $in: facebookFriendsIds } }, ["_id"])).
                map(user => user._id);
        }

    } else if (email) {
        provider = 'email';

        // validate password provided
        if (!password || password.length < 3) {
            throw new Error("password missing")
        }

        // email + password auth
        existingUser = await User.findOne({ email });

        if (existingUser) {
            // login via email + password
            if (isValidPassword(existingUser, password)) {
                return existingUser;

            } else {
                throw new Error("invalid credentials");
            }

        } else {
            const { salt, hash } = hashPassword(password);

            // create new user with email + password
            $filter['email'] = email;

            $set['email'] = email; // upgrading from user token
            $set['password'] = hash;
            $set['passwordSalt'] = salt;
            $set['isAnonymous'] = false;
        }

    } else if (!_id) {
        provider = 'anonymous';

        // anonymous auth
        if (!deviceId) { deviceId = nanoid(); }

        // $filter['devices'] = { id: deviceId, platform: platform };
        $filter['devices.id'] = deviceId;
        $filter['devices.platform'] = platform;

        // only allow anonymous login if account is not connected with external services
        $filter['facebookId'] = { $exists: false };
        $filter['twitterId'] = { $exists: false };
        $filter['googleId'] = { $exists: false };

        $setOnInsert['isAnonymous'] = true;
    }

    /**
     * allow end-user to modify `$setOnInsert` / `$set` values
     */
    hooks.beforeAuthenticate.invoke(provider, $setOnInsert, $set);
    $setOnInsert.metadata.country = country;
    $setOnInsert['username'] = createUserName();

    // has filters, let's find which user matched to update.
    if (Object.keys($filter).length > 0) {
        existingUser = await User.findOne($filter);
    }

    const filter = (existingUser)
        ? { _id: existingUser._id }
        : (_id)
            ? { _id }
            : $filter;

    // find or create user
    await User.updateOne(filter, {
        $setOnInsert,
        $set,
        $addToSet: { friendIds: friendIds }
    }, { upsert: true });

    const currentUser = await User.findOne(filter);

    // Add current user to existing users friend list.
    if (facebookFriendsIds.length > 0) {
        await Promise.all(facebookFriendsIds.map((facebookId) => {
            return User.updateOne({ facebookId }, {
                $addToSet: { friendIds: currentUser._id }
            });
        }));
    }

    return currentUser;
}


async function updateLeaderboard(id, score) {
    if(!leaderBoardData) {
        await loadLeaderboardData();
    }

    let user = await User.findOne({_id: id});
    let added = false;
    if(score > leaderBoardData.minTop) {
        for(let i = 0; i< leaderBoardData.players.length; i++) {
            let player = leaderBoardData.players[i];
            if(player.userId == id) {
                leaderBoardData.players.splice(i, 1);
            }
        }
        for(let i = 0; i< leaderBoardData.players.length; i++) {
            let player = leaderBoardData.players[i];
            if(!added && player.score < score) {
                leaderBoardData.players.splice(i, 0, {rank: i+1, displayName: user.displayName, avatarUrl: user.avatarUrl, userId: id, score: score})
                leaderBoardData.players.pop();
                let $set = {};
                $set["players"] = leaderBoardData.players;
                await Leaderboard.updateOne({_id: LEADER_BOARD_ID}, {
                    $set
                });
                added = true;
            } else {
                player.rank = i+1
            }
        }

        if(added) {

        }
    }
}

async function loadLeaderboardData() {
    leaderBoardData = await Leaderboard.findOne({_id: LEADER_BOARD_ID});
    if(!leaderBoardData) {
        var $setOnInsert:any = {};
        var $set:any = {};
        let players:IPlayer[] = [
            {rank: 1, displayName : "Ayaan", avatarUrl :"",  userId: "default" ,score: 1000},
            {rank: 2, displayName : "Aisha", avatarUrl :"",  userId: "default" ,score: 800},
            {rank: 3, displayName : "Raj", avatarUrl :"",  userId: "default"   ,score: 700},
            {rank: 4, displayName : "Sophie", avatarUrl :"",  userId: "default" ,score: 650},
            {rank: 5, displayName : "Janvi", avatarUrl :"",  userId: "default" ,score: 600},
            {rank: 6, displayName : "Disha", avatarUrl :"",  userId: "default" ,score: 500}];

        $setOnInsert["players"] = players;
        $setOnInsert["maxTop"] = 1000;
        $setOnInsert["minTop"] = 500;

         // find or create user
        await Leaderboard.updateOne({_id: LEADER_BOARD_ID}, {
            $setOnInsert,
            $set
        }, { upsert: true });

        leaderBoardData = await Leaderboard.findOne({_id: LEADER_BOARD_ID});
    }
    return leaderBoardData;
}

export async function syncLeaderBoard() {
    const $set = leaderBoardData;
    const $setOnInsert = leaderBoardData;

    let _id = LEADER_BOARD_ID;
    await Leaderboard.updateOne({ _id }, {
        $setOnInsert,
        $set,
    }, { upsert: true });
};

export function verifySignature(body: any) {
    let payload = body.payload;
    let signature = decode(body.sign);

    return crypto.verify(
        "sha256",
        Buffer.from(payload),
        {
            key: publicKey
        },
        Buffer.from(signature)
    )
}


export async function updateUser(_id: ObjectId, fields: Partial<IUser>) {
    const $set: any = {};

    // filter only exposed fields
    for (const field of UserExposedFields) {
        if (typeof (fields[field]) !== "undefined") {
            if(field === "metadata") {
                if(!$set[field]) {
                    $set[field] = {};
                }
                for (const subField of MetadataExposedFields) {
                    $set[field][subField] = fields[field][subField];
                    if(subField == "score") {
                        await updateLeaderboard( _id, fields[field][subField] )
                    }
                }
            } else {
                $set[field] = fields[field];
            }
        }
    }

    /**
     * default validation: `username` must be unique!
     */
    if ($set['username']) {
        const found = await User.findOne({ username: $set['username'] }, { _id: 1 });
        if (found && found._id !== _id) {
            throw new Error("username taken");
        }
    }

    // trigger custom before user update
    await hooks.beforeUserUpdate.invokeAsync(_id, $set);

    return (await User.updateOne({ _id }, { $set })).nModified > 0;
}

export async function assignDeviceToUser (user: IUser, deviceId: string, platform: Platform) {
    const existingDevice = user.devices.filter(device =>
        device.id === deviceId && device.platform === platform)[0]

    if (!existingDevice) {
        user.devices.push({ id: deviceId, platform: platform });
        await user.save();
    }
}

export async function getOnlineUserCount() {
    return await User.countDocuments({
        updatedAt: { $gte: Date.now() - 1000 * ONLINE_SECONDS }
    });
}

export async function getLeaderboard(id: String) {
    let leaderboard = await Leaderboard.findOne({
        _id: LEADER_BOARD_ID
    });

    let found = false;
    let index = -1;
    for(let i=0; i< leaderboard.players.length ; i++) {
        let player = leaderboard.players[i];
        if(player.userId ===id){
            found = true;
            index = i;
            break;
        }
        index++;
    }

    if(!found) {
        let user = await User.findOne({_id: id});
        leaderboard.players.pop();
        let factor = user.metadata.score / ((leaderboard.maxTop - leaderboard.minTop)/2 + leaderboard.minTop);
        let rank = Math.round(1000 / factor);
        leaderboard.players.push({rank, displayName: user.displayName, avatarUrl: user.avatarUrl, userId: id.toString(), score: user.metadata.score})
    }
    return {leaderboard, index}
}

export async function sendFriendRequest(senderId: ObjectId, receiverId: ObjectId) {
    const isAllowedToSend = await User.findOne({
        _id: receiverId,
        blockedUserIds: { $nin: [senderId] }
    });

    if (isAllowedToSend !== null) {
        return await FriendRequest.updateOne({
            sender: senderId,
            receiver: receiverId
        }, {}, {
            upsert: true
        });

    } else {
        return false;
    }
}

export async function consumeFriendRequest(receiverId: ObjectId, senderId: ObjectId, accept: boolean = true) {
    if (accept) {
        await User.updateOne({ _id: receiverId }, { $addToSet: { friendIds: senderId } });
        await User.updateOne({ _id: senderId }, { $addToSet: { friendIds: receiverId } });
    }
    await FriendRequest.deleteOne({ sender: senderId, receiver: receiverId });
}

export async function blockUser(userId: ObjectId, blockedUserId: ObjectId) {
    await User.updateOne({ _id: userId }, {
        $addToSet: { blockedUserIds: blockedUserId },
        $pull: { friendIds: blockedUserId }
    });
    await User.updateOne({ _id: blockedUserId }, {
        $pull: { friendIds: userId }
    });
    await FriendRequest.deleteOne({ sender: blockedUserId, receiver: userId });
}

export async function unblockUser(userId: ObjectId, blockedUserId: ObjectId) {
    await User.updateOne({ _id: userId }, {
        $addToSet: { friendIds: blockedUserId },
        $pull: { blockedUserIds: blockedUserId }
    });
}

export async function getFriendRequests(userId: ObjectId): Promise<IFriendRequest[]> {
    return await FriendRequest.find({ receiver: userId });
}

export async function getFriendRequestsProfile(
    friendRequests: IFriendRequest[],
    fields: Array<keyof IUser> = DEFAULT_USER_FIELDS,
) {
    return await User.find({ _id: { $in: friendRequests.map(request => request.sender) } }, fields);
}

export async function getFriends(
    user: IUser,
    fields: Array<keyof IUser> = DEFAULT_USER_FIELDS,
) {
    return await User.find({ _id: { $in: user.friendIds } }, fields);
}

export async function getOnlineFriends(
    user: IUser,
    fields: Array<keyof IUser> = DEFAULT_USER_FIELDS,
) {
    return await User.find({
        _id: { $in: user.friendIds },
        updatedAt: { $gte: Date.now() - 1000 * ONLINE_SECONDS }
    }, fields);
}

// re-exports
export {
    verifyToken,
    FriendRequest,
    IFriendRequest,
    User,
    IUser,
    mongoose,
    hooks
};

// export async function logout(userId: string | mongoose.Schema.Types.ObjectId) {
//     return await User.updateOne({ _id: userId }, { $set: { online: false } });
// }

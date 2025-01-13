import crypto from "crypto";
import axios from 'axios';

export const hasher = (() => {
    let password;
    return {
        hashCodeSalted(salt) {
            if (!password) {
                // password is created on first call.
                password = randomizer.getRandomString(128);
            }

            return crypto.createHash("sha3-512")
                .update(password)
                .update(crypto.createHash("sha3-512").update(salt, "utf8").digest("hex"))
                .digest("hex");
        }
    }
})()

export const randomizer = (() => {
    let charCodeLettersOnly = r => 65 <= r && r <= 90;
    let charCodeAllPrintableChars = r => r === 45 || 47 <= r && r <= 57 || 64 <= r && r <= 90 || 97 <= r && r <= 122;

    return {
        getRandomString(length, lettersOnly = false) {
            const charCodeCondition = lettersOnly
                ? charCodeLettersOnly
                : charCodeAllPrintableChars;

            let string = "";
            while (string.length < length) {
                let arr = new Uint16Array(length);
                crypto.webcrypto.getRandomValues(arr);
                arr = Array.apply([], arr); /* turn into non-typed array */
                arr = arr.map(function (r) {
                    return r % 128
                })
                arr = arr.filter(function (r) {
                    /* strip non-printables: if we transform into desirable range we have a probability bias, so I suppose we better skip this character */
                    return charCodeCondition(r);
                });
                string += String.fromCharCode.apply(String, arr);
            }
            return string.substring(0, length)
        }
    }
})()

/*
    cyrb53 (c) 2018 bryc (github.com/bryc)
    A fast and simple hash function with decent collision resistance.
    Largely inspired by MurmurHash2/3, but with a focus on speed/simplicity.
    Public domain. Attribution appreciated.
*/
export const cyrb53 = function(str, seed = 0) {
    let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
    for (let i = 0, ch; i < str.length; i++) {
        ch = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1>>>16), 2246822507) ^ Math.imul(h2 ^ (h2>>>13), 3266489909);
    h2 = Math.imul(h2 ^ (h2>>>16), 2246822507) ^ Math.imul(h1 ^ (h1>>>13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1>>>0);
};

export const fetchCFTurnCredentials = async () => {
    try {
        const TURN_TOKEN_ID = process.env.CF_TURN_TOKEN_ID;
        const TURN_API_TOKEN = process.env.CF_TURN_API_TOKEN;

        if (!TURN_TOKEN_ID || !TURN_API_TOKEN) {
            throw new Error('CF_TURN_TOKEN_ID and CF_TURN_API_TOKEN must be provided in the environment variables.');
        }

        const response = await axios.post(
            `https://rtc.live.cloudflare.com/v1/turn/keys/${TURN_TOKEN_ID}/credentials/generate`,
            { ttl: 31536000 }, // Time to live in seconds for the credentials
            {
                headers: {
                    "Authorization": `Bearer ${TURN_API_TOKEN}`,
                    "Content-Type": "application/json"
                }
            }
        );

        console.log("TURN credentials fetched successfully: ", response.data);

        return {
            "sdpSemantics": "unified-plan",
            "iceServers": [
                {
                    "urls": "stun:stun.cloudflare.com:3478"
                },
                {
                    "urls": "turns:turn.cloudflare.com:5349?transport=tcp",
                    "username": response.data.iceServers.username,
                    "credential": response.data.iceServers.credential
                }
            ]
        };

    } catch (error) {
        console.error("Error fetching TURN credentials:", error);
        process.exit(1); // Exit if we can't fetch TURN credentials
    }
};
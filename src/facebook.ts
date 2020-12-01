import { get } from "httpie";

export async function getFacebookUser (accessToken: string) {
    const fields = 'id,name,friends,email,picture';

    try {
        const req = await get(`https://graph.facebook.com/me?fields=${fields}&access_token=${accessToken}`, {
            headers: { 'Accept': 'application/json' }
        });
        return req.data;
    } catch(ex) {
        console.error(ex);
    }

    // TODO: paginate through user friends

    return null;
}
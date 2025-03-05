import JWTAuth from './auth'

export default {
    async fetch(request): Promise<Response> {


        // Initialize the auth with your secret
        // @ts-ignore
        const auth = new JWTAuth(globalThis.env.SECRET_KEY);


        const newRequest = new Request(request);

        // Set headers using method
        newRequest.headers.set("X-Example", "bar");

        try {
            return await fetch(newRequest);
        } catch (e) {
            // @ts-ignore
            return new Response(JSON.stringify({ error: e.message }), {
                status: 500,
            });
        }
    },
} satisfies ExportedHandler;
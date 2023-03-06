# llegomark-api

This is a Cloudflare worker that acts as a proxy to the OpenAI API that can be used to generate text. It ensures that the client's IP address is hashed and used for rate-limiting purposes, securing the client's privacy. 

It also enforces a maximum number of requests per IP address per hour to prevent abuse of the OpenAI API. The worker checks that the request is coming from an allowed domain and responds with CORS headers accordingly. 

In case of errors or exceptions, the worker returns the appropriate HTTP status code and error message.

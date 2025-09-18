YARP Reverse Proxy

Run locally

- Ensure AuthenticationAPI runs on https://localhost:5001 with /.well-known/jwks.json
- Ensure legacy site is reachable at https://legacy.localtest.me:7443
- Start this project: dotnet run --project ./YARP/YARP.csproj
- Open https://localhost:7000

Notes

- JWT is read from header X-Auth-JWT or cookie AuthJwt
- Monolith routes require claims bcm:selected_role and bcm:selected_scheme
- Proxy rewrites Set-Cookie domain/samesite/secure to PublicCookie settings
- Mirrors AdminBackOffcieCookie into configured X-Session-\* headers on monolith

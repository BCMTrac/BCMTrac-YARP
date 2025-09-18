YARP Reverse Proxy

CI

<<<<<<< HEAD
![CI](https://github.com/Brandon255-rgb/BCMTrac_YARP/actions/workflows/dotnet.yml/badge.svg)
=======
![CI](https://github.com/OWNER/REPO/actions/workflows/dotnet.yml/badge.svg)

Replace OWNER/REPO above with your GitHub org and repository name after you push this repo.
>>>>>>> 922b84a (docs: add GitHub Actions CI badge placeholder to README)

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

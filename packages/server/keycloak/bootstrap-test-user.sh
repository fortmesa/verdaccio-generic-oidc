#!/usr/bin/env bash
# Creates the "alice" test user in the verdaccio-test realm and assigns her
# both a realm role (npm-publish) and a client role (admin, on the
# oauthClientIdName client) -- exercising both claim shapes
# packages/server/src/groups.ts needs to handle. Run this once after
# `docker compose up keycloak` has finished importing keycloak/realm-export.json.
#
# Usage: KC_URL=http://localhost:18080 ./bootstrap-test-user.sh
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:18080}"
REALM=verdaccio-test
CLIENT_ID=oauthClientIdName

token() {
  curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | node -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>console.log(JSON.parse(d).access_token))'
}

TOKEN="$(token)"
AUTH=(-H "Authorization: Bearer $TOKEN")

echo "creating user alice..."
curl -s -o /dev/null -w "  %{http_code}\n" -X POST "$KC_URL/admin/realms/$REALM/users" \
  "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"username":"alice","enabled":true,"email":"alice@example.com","emailVerified":true,
       "firstName":"Alice","lastName":"Test","requiredActions":[],
       "credentials":[{"type":"password","value":"alicepw","temporary":false}]}'

USER_ID=$(curl -s "$KC_URL/admin/realms/$REALM/users?username=alice" "${AUTH[@]}" \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>console.log(JSON.parse(d)[0].id))')
CLIENT_UUID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=$CLIENT_ID" "${AUTH[@]}" \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>console.log(JSON.parse(d)[0].id))')

echo "assigning realm role npm-publish..."
REALM_ROLE=$(curl -s "$KC_URL/admin/realms/$REALM/roles/npm-publish" "${AUTH[@]}")
curl -s -o /dev/null -w "  %{http_code}\n" -X POST "$KC_URL/admin/realms/$REALM/users/$USER_ID/role-mappings/realm" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -d "[$REALM_ROLE]"

echo "assigning client role admin (on client '$CLIENT_ID')..."
CLIENT_ROLE=$(curl -s "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/roles/admin" "${AUTH[@]}")
curl -s -o /dev/null -w "  %{http_code}\n" -X POST "$KC_URL/admin/realms/$REALM/users/$USER_ID/role-mappings/clients/$CLIENT_UUID" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -d "[$CLIENT_ROLE]"

echo "done. Client secret is 'oauthClientIdName-test-secret' (see realm-export.json)."

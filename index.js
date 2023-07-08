// change these
let gameHash =
  'e2fa150d1180331b26907a0f8d6bd40e25d72f7cd2d552c54abd4066ff415b7c';
let gameId = 9;
let commitment =
  'f94680994daea63b619d2540092bd993f8c78a482437cc71a4af8532e6618c2f';

let displayGames = 3; // Only show the first ...

// fixed per appp
let vx_pubkey =
  'b110a624b88aea50b1dbd643d8beb994adef852c7259e7ca2b69c1fa3c82f7a65b4a40d93c539e93ac785d1427f59cb2';
const appSlug = 'demo';

/////////////////////////////
// the logic...
////////////////////////////

const { sha256 } = require('@noble/hashes/sha256');
const { hmac } = require('@noble/hashes/hmac');

const { bytesToHex, hexToBytes } = require('@noble/hashes/utils');
const bls = require('@noble/curves/bls12-381').bls12_381;
const fetch = require('node-fetch');

gameHash = hexToBytes(gameHash);
commitment = hexToBytes(commitment);
vx_pubkey = hexToBytes(vx_pubkey);

let showedSkipMessage = false;
async function run() {
  for (; gameId > 0; gameId--) {
    const currentGameHash = gameHash;
    gameHash = sha256(gameHash);

    if (displayGames-- > 0) {
      const message = gameHash;
      await displayGameOutput(currentGameHash, message, gameId);
    } else if (!showedSkipMessage) {
      showedSkipMessage = true;
      console.log(
        '--- Hold Tight, hashing through the hash chain to find terminating hash ---'
      );
      console.log('----');
    }
  }

  const matchesCommitment = bytesToHex(gameHash) == bytesToHex(commitment);
  console.log(
    'Terminating Hash = ',
    bytesToHex(gameHash),
    ' which matches commitment: ',
    matchesCommitment
  );
}
async function displayGameOutput(currentGameHash, message, gameId) {
  const vxData = await getVxData(appSlug, gameId, commitment);
  if (!vxData) {
    console.error('Could not get vx data for gameId: ', gameId);
    return;
  }
  if (bytesToHex(message) != vxData.message) {
    console.error(
      'Warning: vx message ',
      vxData.message,
      ' does not match for ',
      gameId
    );
  }

  const vxSignature = hexToBytes(vxData.vx_signature);
  const verified = bls.verify(vxSignature, message, vx_pubkey);

  console.log('Game: ', gameId);
  console.log('Hash: ', bytesToHex(currentGameHash));
  console.log(
    'Vx Signature: ',
    vxData.vx_signature,
    '(verfied = ',
    verified,
    ')'
  );

  const res = computeVhempCrashResult(vxSignature, currentGameHash);

  console.log('Crash: ', res, 'x');

  console.log('----');
}

run();

async function getVxData(appSlug, index, commitment) {
  const query = `
query AppsMessagesByIndex($appSlug: String!, $index: Int!, $commitment: String!) {
  appBySlug(slug: $appSlug) {
    id
    name
    vx {
      messagesByIndex(commitment: $commitment, index: $index) {
        vx_signature
        message
      }
    }
  }
}
`;

  const variables = {
    appSlug,
    index,
    commitment: bytesToHex(commitment),
  };

  const response = await fetch('https://server.provablyhonest.com/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query,
      variables,
    }),
  });

  if (response.status !== 200) {
    console.error(
      'Looks like there was a vx lookup error. Status Code: ' + response.status
    );
    console.error('response body: ', await response.text());
    return;
  }

  const json = await response.json();

  const r = json.data.appBySlug?.vx?.messagesByIndex?.[0];
  return r;
}

function computeVhempCrashResult(sig, gameHash) {
  const nBits = 52;
  const hash = bytesToHex(hmac(sha256, sig, gameHash));

  const seed = hash.slice(0, nBits / 4);
  const r = Number.parseInt(seed, 16);

  let X = r / 2 ** nBits; // uniformly distributed in [0; 1)

  return 1 / (1 - X); // 1-X so there's no chance of div-by-zero
}

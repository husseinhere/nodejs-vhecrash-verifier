// change these
let gameHash =
  '0f725029f430ee204ffa4d2e3f5ef96f92dcf242e96a1d1df36e8e61644693b0';
let gameId = 9;
let commitment =
  '3dcd638f4fe4db33315e08007153b6ae0c80681fa366d551d651e3dda3dad49e';

let displayGames = 3; // Only show the first ...

// fixed per appp
let vx_pubkey =
  '82bb9e128159fa868f8115e630440ce13dafa352b9f04c8ec48a4df3ad30d819554a7cc8a2e2431ab7fd151c8542948f';
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

  const response = await fetch(
    'https://ph-server-hrrfydcqhq-uw.a.run.app/graphql',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query,
        variables,
      }),
    }
  );

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

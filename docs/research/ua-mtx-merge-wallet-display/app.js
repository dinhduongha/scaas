// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-mtx-merge T20: one eth_signTypedData_v4 request per row of rows.json; the signature is recovered against the row's
// expected digest (our renderer's), so a match proves the wallet signed the digest we compute. No keys here.
/* global ethers */
const $ = (id) => document.getElementById(id);
const eth = window.ethereum;
const results = {};
let account = null;
let clientVersion = null;
let data = null;

const status = (text) => { $('status').textContent = text; };
const chainHex = () => '0x' + data.chainId.toString(16);
const typesOnly = (types) => Object.fromEntries(Object.entries(types).filter(([k]) => k !== 'EIP712Domain'));

function refreshAll() {
  $('all').value = JSON.stringify({ wallet: clientVersion, userAgent: navigator.userAgent, account, chainId: data.chainId,
    results: data.rows.map((r) => results[r.id] ?? { id: r.id, signed: false }) }, null, 2);
}

async function refreshStatus() {
  if (!eth) return status('no injected wallet (window.ethereum) found');
  const active = parseInt(await eth.request({ method: 'eth_chainId' }), 16);
  const net = active === data.chainId ? 'SCaaS testnet' : `chain ${active}: switch to ${data.chainId} before signing`;
  status(`${account ? `account ${account}` : 'not connected'} · ${net} · ${clientVersion ?? ''}`);
}

$('connect').onclick = async () => {
  [account] = await eth.request({ method: 'eth_requestAccounts' });
  clientVersion = await eth.request({ method: 'web3_clientVersion' }).catch(() => null);
  await refreshStatus();
  refreshAll();
};

$('switch').onclick = async () => {
  try {
    await eth.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: chainHex() }] });
  } catch (e) {
    if (e.code !== 4902) return status(`switch refused: ${e.message}`);
    await eth.request({ method: 'wallet_addEthereumChain', params: [{ chainId: chainHex(), chainName: 'SCaaS testnet',
      rpcUrls: [$('rpc').value], nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 } }] });
  }
  await refreshStatus();
};

async function sign(row, out) {
  if (!account) return (out.textContent = 'connect first');
  const json = JSON.stringify(row.typedData);
  try {
    const signature = await eth.request({ method: 'eth_signTypedData_v4', params: [account, json] });
    const recovered = ethers.recoverAddress(row.digest, signature);
    const match = recovered.toLowerCase() === account.toLowerCase();
    results[row.id] = { id: row.id, primaryType: row.typedData.primaryType, digest: row.digest, signature, recovered, match };
    out.innerHTML = '';
    out.append(`signature ${signature}\nrecovered ${recovered}\n`);
    const verdict = document.createElement('b');
    verdict.className = match ? 'ok' : 'bad';
    verdict.textContent = match ? 'MATCH: the wallet signed our digest' : 'NO MATCH: the wallet signed another digest';
    out.append(verdict);
  } catch (e) {
    results[row.id] = { id: row.id, error: `${e.code ?? ''} ${e.message}` };
    out.textContent = `refused: ${e.code ?? ''} ${e.message}`;
  }
  refreshAll();
}

async function main() {
  data = await (await fetch('rows.json')).json();
  $('cid').textContent = data.chainId;
  for (const row of data.rows) {
    const td = row.typedData;
    // a second, independent rendering of the digest (ethers), before anything is signed
    const local = ethers.TypedDataEncoder.hash(td.domain, typesOnly(td.types), td.message);
    const s = document.createElement('section');
    s.innerHTML = `<h2>${row.id} <span class="muted">in ${td.domain.name}</span></h2>
      <div>expected digest <code>${row.digest}</code> <span class="${local === row.digest ? 'ok' : 'bad'}">ethers: ${
        local === row.digest ? 'same' : local}</span></div>
      <details><summary>Typed data sent and its source</summary><pre></pre></details>
      <button>Sign ${row.id}</button><pre class="out">not signed</pre>`;
    s.querySelector('pre').textContent = `${row.source}\noverrides ${JSON.stringify(row.overrides, null, 2)}\n\n`
      + JSON.stringify(td, null, 2);
    s.querySelector('button').onclick = () => sign(row, s.querySelector('.out'));
    $('rows').append(s);
  }
  $('copy').onclick = () => { $('all').select(); navigator.clipboard?.writeText($('all').value); };
  eth?.on?.('chainChanged', refreshStatus);
  eth?.on?.('accountsChanged', (a) => { account = a[0] ?? null; refreshStatus(); refreshAll(); });
  await refreshStatus();
  refreshAll();
}

main().catch((e) => status(`error: ${e.message}`));

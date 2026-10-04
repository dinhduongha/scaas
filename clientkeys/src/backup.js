// Show-once backup of a NEW recovery phrase, then a verify step before the wallet may be used
// (round-3 design §C.2). States: fresh → revealed → challenged → verified (→ taken).
import { entropyToWords, generateEntropy } from './seed.js';
import { wipe } from './bytes.js';

export class SeedBackup {
  constructor(entropy = generateEntropy()) {
    this._entropy = entropy;
    this.state = 'fresh';
    this._asked = null;
  }

  /** The 24 words, exactly once. Display them, then drop the array. */
  reveal() {
    if (this.state !== 'fresh') throw new Error('The recovery phrase is shown only once.');
    this.state = 'revealed';
    return entropyToWords(this._entropy);
  }

  /** Ask for `count` distinct random positions (1-based for display). */
  challenge(count = 3) {
    if (this.state !== 'revealed' && this.state !== 'challenged') throw new Error('Reveal the phrase first.');
    const picked = new Set();
    const r = new Uint32Array(1);
    while (picked.size < count) {
      crypto.getRandomValues(r);
      picked.add(r[0] % 24);
    }
    this._asked = [...picked].sort((a, b) => a - b);
    this.state = 'challenged';
    return this._asked.map((i) => i + 1);
  }

  /** `answers` = words for the asked positions, in order. A miss asks new positions. */
  verify(answers) {
    if (this.state !== 'challenged') throw new Error('Ask for a challenge first.');
    const words = entropyToWords(this._entropy);
    const ok = this._asked.length === answers.length
      && this._asked.every((i, k) => String(answers[k]).trim().toLowerCase() === words[i]);
    words.fill('');
    if (ok) this.state = 'verified';
    return ok;
  }

  /** Hand the entropy to the vault once verified; this object forgets it. */
  take() {
    if (this.state !== 'verified') throw new Error('Confirm the backup words before using this wallet.');
    const out = this._entropy.slice();
    this.abandon();
    this.state = 'taken';
    return out;
  }

  abandon() {
    wipe(this._entropy);
    this._entropy = null;
    this.state = 'abandoned';
  }
}

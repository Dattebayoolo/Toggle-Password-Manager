/**
 * Toggle Password Manager - Password & Passphrase Generator Engine
 * CSPRNG-powered high-entropy password creation and strength metrics.
 */

export class GeneratorEngine {
  static CHAR_UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // Ambiguous I, O excluded by default if flag checked
  static CHAR_UPPER_ALL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  static CHAR_LOWER = 'abcdefghijkmnopqrstuvwxyz'; // Ambiguous l excluded
  static CHAR_LOWER_ALL = 'abcdefghijklmnopqrstuvwxyz';
  static CHAR_DIGITS = '23456789'; // Ambiguous 0, 1 excluded
  static CHAR_DIGITS_ALL = '0123456789';
  static CHAR_SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  static PASSPHRASE_WORDS = [
    'apple', 'apron', 'armor', 'arrow', 'atlas', 'autumn', 'avocado', 'bacon', 'badge',
    'bagel', 'bamboo', 'banana', 'banner', 'barrel', 'basket', 'battery', 'beacon', 'biscuit',
    'blade', 'blanket', 'blaster', 'blonde', 'bloom', 'breeze', 'bridge', 'bronze', 'bubble',
    'cactus', 'camera', 'candle', 'canyon', 'carpet', 'castle', 'celery', 'cherry', 'cipher',
    'citrus', 'clever', 'clover', 'cobalt', 'coffee', 'comet', 'copper', 'coral', 'cosmos',
    'cotton', 'crater', 'crystal', 'curtain', 'dagger', 'dancer', 'desert', 'diamond', 'dolphin',
    'dragon', 'dynamic', 'eagle', 'echo', 'emerald', 'engine', 'falcon', 'feather', 'ferret',
    'fiddler', 'firefly', 'flamingo', 'forest', 'fossil', 'galaxy', 'garden', 'garnet', 'gazelle',
    'geyser', 'glacier', 'glider', 'goblet', 'granite', 'harbor', 'hawk', 'helmet', 'horizon',
    'hunter', 'hybrid', 'iguana', 'island', 'jacket', 'jaguar', 'javelin', 'jigsaw', 'jungle',
    'katana', 'kelp', 'kernel', 'keyboard', 'knight', 'koala', 'lantern', 'laser', 'lava',
    'legend', 'leopard', 'lightning', 'lizard', 'magnet', 'mango', 'marble', 'matrix', 'meadow',
    'meteor', 'mirror', 'monarch', 'mosaic', 'nebula', 'ninja', 'nucleus', 'oasis', 'obsidian',
    'ocean', 'octopus', 'orchid', 'origami', 'panther', 'pebble', 'pelican', 'penguin', 'phoenix',
    'pillar', 'planet', 'plasma', 'platypus', 'polar', 'prism', 'proton', 'pyramid', 'quantum',
    'radar', 'rainbow', 'ranger', 'raven', 'reef', 'rhino', 'ripple', 'rocket', 'ruby', 'safari',
    'sailor', 'saturn', 'scooter', 'shadow', 'sheriff', 'shield', 'silver', 'siren', 'skater',
    'spark', 'sphinx', 'spider', 'spiral', 'spring', 'stream', 'strider', 'sunbeam', 'tiger',
    'timber', 'topaz', 'tornado', 'toucan', 'tribal', 'trophy', 'tulip', 'turbo', 'turtle',
    'unicorn', 'valiant', 'vector', 'velvet', 'vessel', 'viper', 'vortex', 'walrus', 'warrior',
    'willow', 'wizard', 'wombat', 'zebra', 'zenith', 'zephyr', 'zodiac'
  ];

  /**
   * Generates a random character password
   */
  static generatePassword(options = {}) {
    const {
      length = 16,
      uppercase = true,
      lowercase = true,
      numbers = true,
      symbols = true,
      avoidAmbiguous = false
    } = options;

    let pool = '';
    const guaranteed = [];

    if (uppercase) {
      const set = avoidAmbiguous ? this.CHAR_UPPER : this.CHAR_UPPER_ALL;
      pool += set;
      guaranteed.push(this.getRandomChar(set));
    }
    if (lowercase) {
      const set = avoidAmbiguous ? this.CHAR_LOWER : this.CHAR_LOWER_ALL;
      pool += set;
      guaranteed.push(this.getRandomChar(set));
    }
    if (numbers) {
      const set = avoidAmbiguous ? this.CHAR_DIGITS : this.CHAR_DIGITS_ALL;
      pool += set;
      guaranteed.push(this.getRandomChar(set));
    }
    if (symbols) {
      pool += this.CHAR_SYMBOLS;
      guaranteed.push(this.getRandomChar(this.CHAR_SYMBOLS));
    }

    if (!pool) {
      pool = this.CHAR_LOWER_ALL;
      guaranteed.push(this.getRandomChar(pool));
    }

    const remainingCount = Math.max(0, length - guaranteed.length);
    const randomChars = [];
    const randomBytes = new Uint32Array(remainingCount);
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    cryptoObj.getRandomValues(randomBytes);

    for (let i = 0; i < remainingCount; i++) {
      randomChars.push(pool[randomBytes[i] % pool.length]);
    }

    // Combine and shuffle guaranteed + random
    const combined = [...guaranteed, ...randomChars];
    return this.shuffleArray(combined).join('');
  }

  /**
   * Generates a memorable multi-word passphrase
   */
  static generatePassphrase(wordCount = 4, separator = '-', capitalize = true, addNumber = true) {
    const count = Math.max(3, Math.min(wordCount, 8));
    const randomIndices = new Uint32Array(count);
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    cryptoObj.getRandomValues(randomIndices);

    const words = [];
    for (let i = 0; i < count; i++) {
      let word = this.PASSPHRASE_WORDS[randomIndices[i] % this.PASSPHRASE_WORDS.length];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      words.push(word);
    }

    if (addNumber) {
      const numByte = new Uint8Array(1);
      cryptoObj.getRandomValues(numByte);
      const randomNum = (numByte[0] % 90 + 10).toString(); // 10-99
      words[words.length - 1] += randomNum;
    }

    return words.join(separator);
  }

  static getRandomChar(str) {
    const rand = new Uint32Array(1);
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    cryptoObj.getRandomValues(rand);
    return str[rand[0] % str.length];
  }

  static shuffleArray(arr) {
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    for (let i = arr.length - 1; i > 0; i--) {
      const rand = new Uint32Array(1);
      cryptoObj.getRandomValues(rand);
      const j = rand[0] % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  /**
   * Evaluates password strength, entropy and crack-time
   * Returns: { score: 0-4, label, entropyBits, crackTimeText }
   */
  static evaluateStrength(password) {
    if (!password) {
      return { score: 0, label: 'Empty', entropyBits: 0, crackTimeText: 'Instant' };
    }

    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

    poolSize = Math.max(poolSize, 1);
    const entropyBits = Math.round(password.length * Math.log2(poolSize));

    let score = 0;
    let label = 'Very Weak';
    let crackTimeText = 'Instant';

    if (password.length < 8 || entropyBits < 28) {
      score = 0;
      label = 'Very Weak';
      crackTimeText = 'A few seconds';
    } else if (password.length < 10 || entropyBits < 40) {
      score = 1;
      label = 'Weak';
      crackTimeText = 'A few minutes';
    } else if (password.length < 12 || entropyBits < 56) {
      score = 2;
      label = 'Moderate';
      crackTimeText = 'Several months';
    } else if (password.length < 15 || entropyBits < 75) {
      score = 3;
      label = 'Strong';
      crackTimeText = 'Tens of thousands of years';
    } else {
      score = 4;
      label = 'Very Strong';
      crackTimeText = 'Millions of years';
    }

    return {
      score,
      label,
      entropyBits,
      crackTimeText
    };
  }
}

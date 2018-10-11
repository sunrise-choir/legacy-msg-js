// Read in a directory of files and divides the files it into invalid legacy json
// messages (either not json, or containing invalid floats) and valid ones,
// also computing signing encoding, length and hash of valid data.
//
// Run as `node index.js in_dir out_dir`, where out_dir contains two
// directories named `yay` and `nay`. All invalid data is copied into `nay`,
// valid data as its signing encoding, length and hash is copied into `yay`.
//
// This is intended for usage on an input directory containing corpus data of
// a json fuzzer.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const TextDecoder = require('util').TextDecoder;

const async = require('async');

function decode(str) {
  return JSON.parse(str, (key, value) => {
    if (typeof value === "string") {
      let prev_is_high_surrogate = false;
      for (let code_point_str of value) {
        const code_point = code_point_str.codePointAt(0);
        if (code_point >= 0xD800 && code_point <= 0xDBFF) {
          if (prev_is_high_surrogate) {
            throw "two high surrogates in sequence";
          } else {
            prev_is_high_surrogate = true;
          }
        } else if (code_point >= 0xDC00 && code_point <= 0xDFFF) {
          if (prev_is_high_surrogate) {
            prev_is_high_surrogate = false;
          } else {
            throw "low surrogate without preceeding high surrogate"
          }
        }
      }

    } else if (value === Infinity || value === -Infinity || Object.is(value, -0.0)) {
      throw "invalid numer!"
    }
    return value;
  });
}

// Return a string holding the data encoded for signing. To turn into the utf8 representation, use
// return Buffer.from(encode_signing(data), 'utf8');
function encode_signing(data) {
  return JSON.stringify(data, null, 2);
}

// Compute the length of an encoded msg
function length(str) {
  return str.length;
}

// Compute the hash of an encoded msg.
// Returns a buffer.
function hash(str) {
  const hasher = crypto.createHash('sha256');

  hasher.update(str, 'latin1');
  return hasher.digest();
}

function handle_dir(dir, out) {
  const yay = path.join(out, "yay");
  const nay = path.join(out, "nay");

  fs.readdir(dir, (err, files) => {
    async.eachLimit(files, 32, (file, cb) => {
      fs.readFile(path.join(dir, file), (err, data) => {
        try {
          const data_str = new TextDecoder('utf-8', { fatal: true }).decode(data);

          const enc = encode_signing(decode(data_str));
          const l = length(enc);
          const h = hash(enc);
          const base = path.join(yay, file);

          async.parallel([
            cb => fs.writeFile(base, data, cb),
            cb => fs.writeFile(base + ".json_signing", enc, "utf8", cb),
            cb => fs.writeFile(base + ".length", JSON.stringify(l), "utf8", cb),
            cb => fs.writeFile(base + ".sha256", h, cb)
          ], cb);
        } catch (e) {
          fs.writeFile(path.join(nay, file), data, cb);
        }
      });
    }, err => {
      if (err) {
        console.error(err);
      }
    });
  });
}

handle_dir(process.argv[2], process.argv[3]);

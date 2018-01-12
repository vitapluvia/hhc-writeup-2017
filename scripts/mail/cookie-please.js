'use strict';

const aes256 = require('aes256');

const KEY = 'need to put any length key in here';
const rando_string = () => 'AAAAA';

const cookie_maker = username => {
  const plaintext = rando_string(5)
  const ciphertext = aes256.encrypt(KEY, plaintext).replace(/\=/g,'');

  return ciphertext;
};

const cookie_checker = req => {
  const thecookie = JSON.parse(req.cookies.EWA);
  const ciphertext = thecookie.ciphertext;
  const username = thecookie.name
  const plaintext = aes256.decrypt(KEY, ciphertext);

  if (plaintext === thecookie.plaintext) {
    return true;
  }

  return false;
};

const ciphertext = cookie_maker('foo');

let cipherSlice = new Buffer(ciphertext, 'base64').toString('ascii');
console.log(`Cipher Slice Length: ${cipherSlice.length}`);
cipherSlice = cipherSlice.slice(0, cipherSlice.length - 5);
console.log(`New Cipher Slice Length: ${cipherSlice.length}`);
cipherSlice = new Buffer(cipherSlice).toString('base64').replace(/\=/g, '');
console.log(`Cipher Slice: ${cipherSlice}`);

const cookie = {
  cookies: {
    // 'EWA': `{"name":"alabaster.snowball@northpolechristmastown.com","plaintext":"","ciphertext":"${cipherSlice}"}`
    'EWA': `{"name":"jessica.claus@northpolechristmastown.com","plaintext":"","ciphertext":"${cipherSlice}"}`
  }
};

console.log(cookie_checker(cookie));
console.log(`Cookie: \n${cookie.cookies.EWA}`);

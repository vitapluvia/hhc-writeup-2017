'use strict';

const known = require('./known.json');
const infractions = require('./out.json').infractions;

/* @NOTE: Had to manually clean name 'Felix McLean' in known naughty,
 *        case did not match from BOLO naughty list to live site.
 */

const groupedInfractions = {};

infractions.forEach(x => {
  groupedInfractions[x.name] = groupedInfractions[x.name] || [];
  groupedInfractions[x.name].push(x);
});

// ----------- FIND NAUGHTY LIMIT BASED ON BOLO -------------- //

const naughtyFound = Object.keys(groupedInfractions)
  .filter(name => known.naughty.indexOf(name) !== -1)

const niceFound = Object.keys(groupedInfractions)
  .filter(name => known.nice.indexOf(name) !== -1)

const getInfractionCount = list => {
  return list.map(value =>
    groupedInfractions[value].length
  ).sort()
};

const minNaughtyCount = Math.min(...getInfractionCount(naughtyFound))
const maxNiceCount = Math.max(...getInfractionCount(niceFound))

console.log(`Minimum Naughty Infraction Count: ${minNaughtyCount}`);
console.log(`Maximum Nice Infraction Count: ${maxNiceCount}`);
console.log(`\n> It takes ${minNaughtyCount} infractions to land on the naughty list.\n`);

// --------------- FIND MOLES BASED ON BOLO ------------------ //

const moleInfractions = new Set(infractions.filter(inf => {
  return known.moles.indexOf(inf.name) !== -1;
}).map(x => x.title));

const molesFound = Object.keys(groupedInfractions).filter(name => {
  const curInfractions = groupedInfractions[name];
  const moleInfractionsFound = curInfractions.reduce((acc, infr) =>
    acc + (moleInfractions.has(infr.title) ? 1 : 0), 0);

  return moleInfractionsFound >= 3 && groupedInfractions[name].length >= 4;
});

console.log(`> ${molesFound.length} Moles Found:\n`);
console.log(`${molesFound.map(x => '- ' + x).join('\n')}\n`);

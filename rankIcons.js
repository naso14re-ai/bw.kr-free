export function getPublicRankFlags(runlevel) {
  return {
    runlevel,
    bigowner: runlevel === 8,
    radical: runlevel === 7,
    developer: runlevel === 6,
    contributor: runlevel === 5,
    dj: runlevel === 1.75,
    gavel: runlevel === 4,
    crown: runlevel === 3,
    lowcrown: runlevel === 2,
    broom: runlevel === 1.05,
    angel: runlevel === 1,
  };
}

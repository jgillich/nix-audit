'use strict';

const zlib = require('zlib');
const request = require('request');
const async = require('async');
const XmlStream = require('xml-stream');
const semver = require('semver');
const _ = require('underscore');

function packages(cb) {
  let data = '';
  request('https://nixos.org/nixpkgs/packages.json.gz')
    .pipe(zlib.createUnzip())
    .on('data', (chunk) => data += chunk)
    .on('error', onError)
    .on('end', () => cb(JSON.parse(data)));
}

function scan(packages, year, cb) {
  let res = request(`http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-${year}.xml.gz`);
  let xml = new XmlStream(res.pipe(zlib.createUnzip()).on('error', onError));

  xml.collect('vuln:product');
  xml.on('end', cb);
  xml.on('error', onError);
  xml.on('endElement: entry', function(entry) {
    if(!entry['vuln:vulnerable-software-list']) return;

    let pkgs = entry['vuln:vulnerable-software-list']['vuln:product']
      .map(p => {
        let parts = p.split(':');
        let pkg = {
          name: parts[3],
          version: parts[4]
        };
        if(!packages.hasOwnProperty(pkg.name)) {
          return null;
        }
        let match = /(?:(\d+)\.)?(?:(\d+)\.)?(?:(\d+)\.\d+)$/.exec(packages[pkg.name].name);
        if(match === null || !semver.valid(match[0]) || !semver.valid(pkg.version) || !semver.eq(match[0], pkg.version)) {
          return null;
        }
        return pkg;
      })
      .filter(p =>  p !== null);

    if(pkgs.length) {
      console.log(`${entry['vuln:cvss']['cvss:base_metrics']['cvss:score']} ${entry['vuln:cve-id']} `
        + _.uniq(pkgs.map(p => packages[p.name].name)).join(' ')
        + `\n${entry['vuln:summary']}\n`);
    }
  });
}

function onError(err) {
  if(err) {
    console.error(err.message);
    process.exit(1);
  }
}

packages(function(packages) {
  let years = [2010, 2011, 2012, 2013, 2014, 2015];
  async.mapSeries(years, scan.bind(null, packages), onError);
});

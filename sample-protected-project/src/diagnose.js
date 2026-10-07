const fs = require('fs')

const config = JSON.parse(fs.readFileSync('config/database.json', 'utf8'))
const database = config.database

if (database.port !== database.expectedPort) {
  console.error(`E_PORT_MISMATCH configured=${database.port} expected=${database.expectedPort} host=${database.host} database=${database.name}`)
  process.exitCode = 7
} else {
  console.log(`Database configuration is consistent for ${database.host}/${database.name}`)
}

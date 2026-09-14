// Run: NODE_OPTIONS="--import ../../js/src/auto.mjs" node examples/node/app.js
console.info('Subscription updated');
console.error('User not found');
require('../../js/src/index.cjs').log(17, 'explicit attrs call', 'payment.charge.failed', { id: 123 });
throw new Error('unhandled — watch this become a FATAL record, then crash normally');

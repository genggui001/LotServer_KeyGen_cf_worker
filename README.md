# LotServer License Generator

A Cloudflare Worker that generates custom LotServer license files based on provided MAC addresses.

## Features

- Generate license files with custom MAC addresses
- Support for different license versions (0 and 1)
- Extended license validity (until 2099)
- Verbose mode for debugging

## Deployment

### Prerequisites
- [Node.js](https://nodejs.org/) (v14 or later)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- A Cloudflare account

### Steps to deploy

1. Clone this repository:
```bash
git clone https://github.com/yourusername/lotserver-license-generator.git
cd lotserver-license-generator
```

2. Install dependencies:
```bash
npm install
```

3. Authenticate with Cloudflare:
```bash
npx wrangler login
```

4. Deploy the worker:
```bash
npm run deploy
```

## Usage

Once deployed, you can generate license files by accessing your worker URL with the following parameters:

- `mac`: MAC address in format `00:00:00:00:00:00` (required)
- `ver`: Version of the license (0 or 1, default is 1)
- `v`: Enable verbose output (set to `true` to enable)

### Examples

Basic usage:
```
https://lotserver-license-generator.your-worker.workers.dev/?mac=00:11:22:33:44:55
```

Using version 0 with verbose output:
```
https://lotserver-license-generator.your-worker.workers.dev/?mac=00:11:22:33:44:55&ver=0&v=true
```

## Development

To run the worker locally:
```bash
npm run dev
```

## License

This project is intended for educational purposes only.
```

## Deployment Instructions

1. Install Wrangler CLI if you haven't already:
```bash
npm install -g wrangler
```

2. Navigate to the project directory and install dependencies:
```bash
npm install
```

3. Log in to your Cloudflare account:
```bash
wrangler login
```

4. Deploy the worker:
```bash
wrangler deploy
```

Your worker will be accessible at the URL provided after deployment. You can then generate license files by accessing the URL with the appropriate parameters.
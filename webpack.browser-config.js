const path = require('path');
const webpack = require('webpack');

module.exports = {
  target: 'web',
  entry: './src/index.ts',
  output: {
    path: path.resolve(__dirname, 'dist/browser'),
    filename: 'index.js',
  },
  resolve: {
    extensions: ['.js', '.ts', '.tsx', '.json'],
    alias: {
      buffer: require.resolve('buffer/')
    },
    fallback: {
      'stream': require.resolve('stream-browserify'),
      'crypto': require.resolve('crypto-browserify'),
    }
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: [{
          loader: 'ts-loader',
          options: {
            configFile: path.resolve(__dirname, 'tsconfig.json')
          }
        }],
        exclude: /node_modules/,
      },
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              [
                '@babel/preset-env',
                {
                  'useBuiltIns': 'entry'
                }
              ]
            ]
          }
        }
      }
    ]
  },
  node: {
    __dirname: true
  },
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    })
  ],
  optimization: {
    minimize: false
  }
};

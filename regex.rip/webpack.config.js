const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin')

module.exports = {
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  entry: './src/index.tsx',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.scss$/,
        use: ['style-loader',  'css-loader', 'sass-loader'],
        exclude: /node_modules/,
      },
      {
        test: /\.otf$/,
        use: 'url-loader'
      },
      {
        test: /\.png$/,
        use: {
          loader: 'file-loader',
          options: {
            outputPath: 'build',
            publicPath: '/build'
          }
        }
      },
    ],
  },
  resolve: {
    modules: [path.resolve('.'), 'node_modules'],
    extensions: [ '.tsx', '.ts', '.js', '.scss' ],
  },
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'build'),
  },
  plugins: [
    new HtmlWebpackPlugin({
      filename: 'index.html',
      template: 'index.html'
    })
  ],
};



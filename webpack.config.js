const path = require("path");
const webpack = require("webpack");
const CopyWebpackPlugin = require("copy-webpack-plugin");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const srcPath = [__dirname, "src"];
const jsPath = [...srcPath, "ui", "js"];
const htmlPath = [...srcPath, "ui", "html"];

const config = mode => {
  const isDevelopment = mode === "development";
  return {
    watch: isDevelopment ? true : false,
    devtool: isDevelopment ? "source-map" : "",
    mode: mode,
    entry: {
      frida: path.join(...[...srcPath, "frida-scripts", "index.ts"]),
      ui: path.join(...[...jsPath, "index.tsx"])
    },
    output: {
      path: path.join(__dirname, "build"),
      filename: "[name].bundle.js"
    },
    module: {
      rules: [
        {
          test: /\.css$/,
          exclude: /node_modules/,
          loader: "css-loader"
        },
        {
          test: /\.ts(x?)$/,
          exclude: /node_modules/,
          use: {
            loader: "ts-loader",
            options: {
              onlyCompileBundledFiles: true
            }
          }
        },
        {
          enforce: "pre",
          test: /\.js$/,
          loader: "source-map-loader"
        }
      ]
    },
    resolve: { extensions: [".ts", ".tsx", ".js", ".jsx"] },
    plugins: [
      new webpack.DefinePlugin({
        DEV: isDevelopment
      }),
      new CopyWebpackPlugin({
        patterns: [
          {
            from: path.join(...[...htmlPath, "manifest.json"]),
            flatten: true
          }
        ]
      }),
      new HtmlWebpackPlugin({
        template: path.join(...[...htmlPath, "index.html"]),
        favicon: path.join(...[...htmlPath, "favicon.ico"]),
        filename: "index.html",
        chunks: ["ui"]
      })
    ],
    externals: {
      react: "React",
      "react-dom": "ReactDOM"
    }
  };
};

module.exports = (_, argv) => {
  const { mode } = argv;
  return config(mode);
};

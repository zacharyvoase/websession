const lightningCSS = require('@11tyrocks/eleventy-plugin-lightningcss');
const markdownIt = require('markdown-it');
const markdownItAttrs = require('markdown-it-attrs');
const markdownItHighlightJs = require('markdown-it-highlightjs');

const markdown = markdownIt({
  html: true,
  linkify: true,
  typographer: true,
}).use(markdownItHighlightJs, {})
  .use(markdownItAttrs, {});

module.exports = (config) => {
  config.addFilter('smartquotes', (post) => { return smartquotes(post); });
  config.addPlugin(lightningCSS);
  config.setLibrary('md', markdown);
};

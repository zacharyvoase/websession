const lightningCSS = require('@11tyrocks/eleventy-plugin-lightningcss');
const markdownIt = require('markdown-it');
const markdownAnchor = require('markdown-it-anchor');

const markdown = markdownIt({
  html: true,
  linkify: true,
  typographer: true,
}).use(require('markdown-it-highlightjs'), {})
  .use(markdownAnchor, { permalink: markdownAnchor.permalink.headerLink() })
  .use(require('markdown-it-attrs'), {})
  .use(require('markdown-it-toc-done-right'), {level: 2});

module.exports = (config) => {
  config.addFilter('smartquotes', (post) => { return smartquotes(post); });
  config.addPlugin(lightningCSS);
  config.setLibrary('md', markdown);
};

const Arborist = require("@npmcli/arborist");
const fs = require("fs");

async function getDependencyTree(packageName) {
  const arb = new Arborist({
    registry: "https://registry.npmjs.org",
    token: "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",
    authToken: "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",
  });
  try {
    const idealTree = await arb.buildIdealTree({
      add: [packageName],
    });
    const packageNames = [];
    idealTree.children.forEach((node) => {
      packageNames.push(`${node.name}@${node.version}`);
    });
    return packageNames;
  } catch (error) {
    console.error(`Failed to fetch dependency tree for ${packageName}:`, error);
    return [];
  }
}

/**
 * Write dependency list to a file
 * @param {string[]} packages - List of package dependencies
 * @param {string} filename - Output filename
 */
function writeToFile(packages, filename) {
  try {
    fs.writeFileSync(filename, packages.join("\n"), "utf8");
    console.log(`Dependencies written to ${filename}`);
  } catch (error) {
    console.error(`Failed to write to file ${filename}:`, error);
    process.exit(1);
  }
}

const packageArg = process.argv[2];
const outputFile = process.argv[3];

if (!packageArg) {
  console.error("Please provide a package name as an argument");
  process.exit(1);
}

if (!outputFile) {
  console.error("Please provide an output filename as the second argument");
  process.exit(1);
}

getDependencyTree(packageArg)
  .then((packages) => {
    writeToFile(packages, outputFile);
  })
  .catch((err) => {
    console.error("Error:", err);
    process.exit(1);
  });

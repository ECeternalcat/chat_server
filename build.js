// build.js (最终解决方案 v7 - 采纳用户建议，直接复制 node_modules)
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const BUNDLE_DIR = 'dist';
const BLOB_PATH = path.join(BUNDLE_DIR, 'prep.blob');
const CONFIG_PATH = path.join(BUNDLE_DIR, 'sea-config.json');
const EXECUTABLE_NAME = 'chatapp';

const log = (message) => console.log(`\x1b[32m[BUILD]\x1b[0m ${message}`);
const error = (message) => console.error(`\x1b[31m[ERROR]\x1b[0m ${message}`);

try {
    // 1. 清理工作
    log('Cleaning up previous build...');
    if (fs.existsSync(BUNDLE_DIR)) {
        fs.rmSync(BUNDLE_DIR, { recursive: true, force: true });
    }
    fs.mkdirSync(BUNDLE_DIR);

    // 2. 无需打包业务逻辑
    log('Skipping bundling. Using server.js directly.');

    // 3. 创建 SEA 配置
    log('Creating SEA configuration...');
    const assets = {};
    const publicDir = 'public';
    if (fs.existsSync(publicDir)) {
        fs.readdirSync(publicDir).forEach(file => {
            assets[file] = path.join(publicDir, file);
        });
    }
    log(`Found ${Object.keys(assets).length} assets.`);
    const seaConfig = {
        main: 'server.js',
        output: BLOB_PATH,
        disableExperimentalSEAWarning: true,
        assets
    };
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(seaConfig, null, 2));
    log(`SEA config written to ${CONFIG_PATH}`);

    // 4. 生成 Blob
    log('Generating SEA preparation blob...');
    execSync(`node --experimental-sea-config ${CONFIG_PATH}`, { stdio: 'inherit' });
    log('Blob generation successful.');

    // 5. 创建可执行文件
    const nodePath = process.execPath;
    const exeExtension = process.platform === 'win32' ? '.exe' : '';
    const finalExecutablePath = path.join(BUNDLE_DIR, `${EXECUTABLE_NAME}${exeExtension}`);
    log(`Copying Node.js binary to ${finalExecutablePath}...`);
    fs.copyFileSync(nodePath, finalExecutablePath);

    // 6. 注入 Blob
    log('Injecting blob into the executable...');
    const postjectCmd = ['npx postject', finalExecutablePath, 'NODE_SEA_BLOB', BLOB_PATH, '--sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'];
    if (process.platform === 'darwin') {
        postjectCmd.push('--macho-segment-name NODE_SEA');
    }
    execSync(postjectCmd.join(' '), { stdio: 'inherit' });
    log('Injection successful!');
    
    // --- 【【【 最终、最简单的解决方案：直接复制整个 node_modules 】】】 ---
    log('Copying the entire local node_modules directory...');
    log('This is the most robust way to ensure all dependencies are included.');

    const sourceNodeModules = 'node_modules';
    const targetNodeModules = path.join(BUNDLE_DIR, 'node_modules');

    if (fs.existsSync(sourceNodeModules)) {
        fs.cpSync(sourceNodeModules, targetNodeModules, { recursive: true });
        log('Finished copying node_modules.');
    } else {
        error('CRITICAL: `node_modules` directory not found in the project root. Please run `npm install` first.');
        throw new Error('node_modules not found');
    }

    log(`\n✅✅✅ Build Succeeded! Your package is now truly portable. ✅✅✅`);
    log(`   The final package is in the '${BUNDLE_DIR}' directory.`);
    log(`\n=== HOW TO RUN ===`);
    log(`   Run the executable file DIRECTLY from within the '${BUNDLE_DIR}' folder.`);
    log(`   (e.g., by double-clicking chatapp.exe on Windows)`);


} catch (e) {
    error('Build process failed:');
    console.error(e.message);
    process.exit(1);
}
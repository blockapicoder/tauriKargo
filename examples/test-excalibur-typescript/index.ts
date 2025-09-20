// src/main.ts
import * as ex from 'excalibur';

// --- Engine (configure physique ici) ---
const engine = new ex.Engine({
  width: 800,
  height: 600,
  displayMode: ex.DisplayMode.FitScreen,
  backgroundColor: ex.Color.fromHex('#0b0b12'),
  physics: {
    solver: ex.SolverStrategy.Arcade,
    gravity: ex.vec(0, 0)
  }
});
document.getElementById('game')!.appendChild(engine.canvas);

// --- UI ---
const font = new ex.Font({ size: 18, family: 'monospace', color: ex.Color.fromHex('#e8e8f0') });
const scoreLabel = new ex.Label({ text: 'Score: 0', pos: ex.vec(12, 10), font });
const livesLabel = new ex.Label({ text: 'Vies: 3', pos: ex.vec(788, 10), font }); livesLabel.anchor = ex.vec(1, 0);
const levelLabel = new ex.Label({ text: 'Niveau 1', pos: ex.vec(400, 10), font }); levelLabel.anchor = ex.vec(0.5, 0);
engine.add(scoreLabel); engine.add(livesLabel); engine.add(levelLabel);

// --- État ---
let gameOver = false;
let level = 1, score = 0, lives = 3;
let lastShot = -Infinity, fireCooldown = 320; // ms
let invulnUntil = 0;
let alienDir = 1;
const baseAlienSpeed = 30; // px/s
const alienBounds = { left: 40, right: 760 };
const cols = 10, rows = 5, startX = 80, startY = 100, gapX = 56, gapY = 42;

// --- Joueur ---
const player = new ex.Actor({ x: 400, y: 560, width: 48, height: 24, color: ex.Color.fromHex('#39ff88') });
player.body.collisionType = ex.CollisionType.Active;
player.addTag('player');
engine.add(player);

// --- Component pour stocker les métadonnées Alien ---
class AlienData extends ex.Component {
  constructor(public row: number, public points: number) { super(); }
}

// --- Helper Collider -> Actor ---
const otherAsActor = (evt: { other: ex.Collider }): ex.Actor | null => {
  const owner = evt.other?.owner;
  return owner instanceof ex.Actor ? owner : null;
};

// --- Projectiles ---
const addPlayerBullet = (x: number, y: number) => {
  const b = new ex.Actor({ x, y, width: 4, height: 12, color: ex.Color.White });
  b.body.collisionType = ex.CollisionType.Passive; // "sensor-like"
  b.addTag('playerBullet');
  b.vel = ex.vec(0, -520);

  b.on('postupdate', () => { if (b.pos.y < -40) b.kill(); });

  b.on('collisionstart', (evt) => {
    const other = otherAsActor(evt);
    if (other?.hasTag('alien')) {
      b.kill();
      const data = other.get(AlienData) as AlienData | undefined;
      other.kill();
      addPoints(data?.points ?? 10);
      checkWaveCleared();
    }
  });

  engine.add(b);
};

const addEnemyBullet = (x: number, y: number) => {
  const b = new ex.Actor({ x, y, width: 4, height: 12, color: ex.Color.fromHex('#ff6464') });
  b.body.collisionType = ex.CollisionType.Passive;
  b.addTag('enemyBullet');
  b.vel = ex.vec(0, 280 + 10 * level);
  b.on('postupdate', () => { if (b.pos.y > 640) b.kill(); });
  engine.add(b);
  return b;
};

// --- Aliens ---
let aliens: ex.Actor[] = [];

function spawnWave() {
  alienDir = 1;
  aliens = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const x = startX + c * gapX;
      const y = startY + r * gapY;
      const a = new ex.Actor({ x, y, width: 28, height: 20, color: ex.Color.fromHex('#9ddbff') });
      a.body.collisionType = ex.CollisionType.Fixed;
      a.addTag('alien');
      a.addComponent(new AlienData(r, (rows - r) * 10)); // ← on stocke row/points ici

      // défaite si un alien descend trop
      a.on('postupdate', () => {
        if (!gameOver && a.isActive && a.pos.y >= 520) endGame(false);
      });

      engine.add(a);
      aliens.push(a);
    }
  }
  levelLabel.text = 'Niveau ' + level;
}

const livingAliens = () => aliens.filter(a => a.isActive);

function checkWaveCleared() {
  if (livingAliens().length === 0) {
    level++;
    engine.clock.schedule(() => spawnWave(), 800);
  }
}

// --- Mouvement horizontal + descente ---
engine.on('postupdate', (evt) => {
  if (gameOver) return;
  const dt = evt.elapsed / 1000;
  const living = livingAliens();
  if (living.length === 0) return;

  const speed = (baseAlienSpeed + 8 * (level - 1) + (60 - living.length)) * alienDir;
  const dx = speed * dt;

  let minX = +Infinity, maxX = -Infinity;
  for (const a of living) {
    a.pos.x += dx;
    minX = Math.min(minX, a.pos.x);
    maxX = Math.max(maxX, a.pos.x);
  }
  if (minX < alienBounds.left || maxX > alienBounds.right) {
    alienDir *= -1;
    for (const a of living) a.pos.y += 14;
  }
});

// --- Tirs ennemis réguliers (alien le plus bas par colonne) ---
const enemyShootTimer = new ex.Timer({
  fcn: () => {
    if (gameOver) return;
    const live = livingAliens();
    if (live.length === 0) return;

    const byCol = new Map<number, ex.Actor>();
    for (const a of live) {
      const colKey = Math.round((a.pos.x - startX) / gapX);
      const prev = byCol.get(colKey);
      if (!prev || a.pos.y > prev.pos.y) byCol.set(colKey, a);
    }
    const shooters = Array.from(byCol.values());
    const shooter = shooters[(Math.random() * shooters.length) | 0];
    const b = addEnemyBullet(shooter.pos.x, shooter.pos.y + 14);

    b.on('collisionstart', (evt) => {
      const other = otherAsActor(evt);
      if (other?.hasTag('player') && !gameOver) {
        if (engine.clock.now() < invulnUntil) return;
        b.kill();
        hitPlayer();
      }
    });
  },
  interval: 700,
  repeats: true
});
engine.add(enemyShootTimer);
enemyShootTimer.start();

// --- Entrées ---
engine.on('preupdate', () => {
  if (gameOver) return;

  const kb = engine.input.keyboard;
  const speed = 320;
  const left = kb.isHeld(ex.Keys.Left) || kb.isHeld(ex.Keys.A);
  const right = kb.isHeld(ex.Keys.Right) || kb.isHeld(ex.Keys.D);
  player.vel.x = left ? -speed : right ? speed : 0;

  if (kb.wasPressed(ex.Keys.Space) && engine.clock.now() - lastShot >= fireCooldown) {
    addPlayerBullet(player.pos.x, player.pos.y - 20);
    lastShot = engine.clock.now();
  }
  if (kb.wasPressed(ex.Keys.R)) resetGame();
});

// --- Joueur touche un alien (contact direct) ---
player.on('collisionstart', (evt) => {
  const other = otherAsActor(evt);
  if (other?.hasTag('alien') && !gameOver) {
    endGame(false);
  }
});

// --- Score / vies ---
function addPoints(n: number) { score += n; scoreLabel.text = 'Score: ' + score; }

function hitPlayer() {
  lives--; livesLabel.text = 'Vies: ' + lives;
  invulnUntil = engine.clock.now() + 600;
  engine.clock.schedule(() => (player.graphics.opacity = 1), 600);
  player.graphics.opacity = 0.3;
  if (lives <= 0) endGame(false);
}

function endGame(victory: boolean) {
  gameOver = true;
  const title = new ex.Label({
    text: victory ? 'Vous avez gagné !' : 'Game Over',
    pos: ex.vec(400, 280),
    font: new ex.Font({ size: 36, family: 'monospace', color: ex.Color.White })
  });
  title.anchor = ex.vec(0.5, 0.5);

  const sub = new ex.Label({
    text: 'R pour recommencer',
    pos: ex.vec(400, 320),
    font: new ex.Font({ size: 18, family: 'monospace', color: ex.Color.fromHex('#c9c9d8') })
  });
  sub.anchor = ex.vec(0.5, 0.5);

  engine.add(title); engine.add(sub);
}

function resetGame() {
  gameOver = false; level = 1; score = 0; lives = 3;
  alienDir = 1; lastShot = -Infinity; invulnUntil = 0;
  scoreLabel.text = 'Score: 0'; livesLabel.text = 'Vies: 3'; levelLabel.text = 'Niveau 1';

  for (const a of aliens) a.kill(); aliens = [];

  engine.currentScene.actors
    .filter(a => a !== player && a !== scoreLabel && a !== livesLabel && a !== levelLabel)
    .forEach(a => {
      if ((a as any).hasTag?.('playerBullet') || (a as any).hasTag?.('enemyBullet')) a.kill();
    });

  player.pos = ex.vec(400, 560);
  player.vel = ex.vec(0, 0);
  player.graphics.opacity = 1;

  spawnWave();
}

// --- Lancer ---
spawnWave();
engine.start();

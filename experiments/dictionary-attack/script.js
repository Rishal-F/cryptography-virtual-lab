// Predefined candidates are tried in this order during the dictionary attack.
const CANDIDATE_PASSWORDS = [
  'admin',
  '123456',
  'password',
  'qwerty',
  'letmein'
];

/**
 * Hash a password with SHA-256 and return the digest as hexadecimal text.
 *
 * TextEncoder converts the password into bytes before the Web Crypto API
 * computes the SHA-256 digest.
 *
 * @param {string} password - Password to hash.
 * @returns {Promise<string>} Lowercase hexadecimal SHA-256 hash.
 */
async function sha256Hash(password) {
  const encodedPassword = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest('SHA-256', encodedPassword);
  const hashBytes = new Uint8Array(digest);

  return Array.from(hashBytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Compare a candidate password's SHA-256 hash with a target hash.
 *
 * @param {string} candidatePassword - Candidate password to compare.
 * @param {string} targetHash - Expected SHA-256 hash in hexadecimal form.
 * @returns {Promise<boolean>} Whether the candidate matches the target hash.
 */
async function comparePasswordHash(candidatePassword, targetHash) {
  const candidateHash = await sha256Hash(candidatePassword);
  return candidateHash === targetHash.toLowerCase();
}

/**
 * Try each predefined candidate against a target hash.
 *
 * Candidate generation and iteration happen in dictionary order. Once a
 * candidate matches, the attack stops immediately because testing any later
 * candidates cannot change the successful result and would add unnecessary
 * work.
 *
 * @param {string} targetHash - SHA-256 hash to search for.
 * @returns {Promise<{
 *   found: boolean,
 *   password: string|null,
 *   attempts: number,
 *   targetHash: string,
 *   testedCandidates: string[],
 *   candidateHashes: string[]
 * }>} Details of the dictionary attack.
 */
async function dictionaryAttack(targetHash) {
  const testedCandidates = [];
  const candidateHashes = [];

  for (const candidatePassword of CANDIDATE_PASSWORDS) {
    const candidateHash = await sha256Hash(candidatePassword);
    testedCandidates.push(candidatePassword);
    candidateHashes.push(candidateHash);

    // Match detection ends the attack as soon as the target is found.
    if (candidateHash === targetHash.toLowerCase()) {
      return {
        found: true,
        password: candidatePassword,
        attempts: testedCandidates.length,
        targetHash,
        testedCandidates,
        candidateHashes
      };
    }
  }

  return {
    found: false,
    password: null,
    attempts: testedCandidates.length,
    targetHash,
    testedCandidates,
    candidateHashes
  };
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function isValidTargetHash(targetHash) {
  return /^[a-f0-9]{64}$/i.test(targetHash);
}

function initializeDictionaryAttackUI() {
  const targetPasswordInput = document.getElementById('target-password');
  const generateHashButton = document.getElementById('generate-hash');
  const targetHashOutput = document.getElementById('target-hash');
  const startAttackButton = document.getElementById('start-attack');
  const resetAttackButton = document.getElementById('reset-attack');
  const attackStatus = document.getElementById('attack-status');
  const currentCandidate = document.getElementById('current-candidate');
  const attemptCount = document.getElementById('attempt-count');
  const attackProgress = document.getElementById('attack-progress');
  const attackLog = document.getElementById('attack-log');
  const attackResult = document.getElementById('attack-result');

  if (
    !targetPasswordInput ||
    !generateHashButton ||
    !targetHashOutput ||
    !startAttackButton ||
    !resetAttackButton ||
    !attackStatus ||
    !currentCandidate ||
    !attemptCount ||
    !attackProgress ||
    !attackLog ||
    !attackResult
  ) {
    return;
  }

  let targetHash = '';
  let attackRunning = false;
  let attackRunId = 0;

  function clearAttackOutput() {
    currentCandidate.textContent = 'None';
    attemptCount.textContent = '0';
    attackProgress.value = 0;
    attackLog.textContent = '';
    attackResult.textContent = '';
  }

  function setButtonsForAttackState() {
    startAttackButton.disabled = attackRunning;
    generateHashButton.disabled = attackRunning;
  }

  function addAttackLogEntry(attempt, candidate, candidateHash, matched) {
    const logEntry = document.createElement('p');
    logEntry.textContent =
      `Attempt ${attempt}: Candidate "${candidate}" | ` +
      `SHA-256: ${candidateHash} | ${matched ? 'Match' : 'No Match'}`;
    attackLog.appendChild(logEntry);
  }

  // Generate the target hash without exposing the target password in the UI.
  async function generateTargetHash() {
    if (attackRunning) {
      return;
    }

    const password = targetPasswordInput.value;
    if (!password) {
      targetHash = '';
      targetHashOutput.textContent = 'Enter a target password before generating a hash.';
      attackStatus.textContent = 'Validation error';
      attackResult.textContent = '';
      return;
    }

    try {
      targetHash = await sha256Hash(password);
      targetHashOutput.textContent = targetHash;
      clearAttackOutput();
      attackStatus.textContent = 'Target hash generated. Ready to start the attack.';
      startAttackButton.disabled = false;
    } catch (error) {
      targetHash = '';
      targetHashOutput.textContent = 'Unable to generate the target hash.';
      attackStatus.textContent = 'Error';
      attackResult.textContent = 'The Web Crypto API could not generate the target hash.';
      console.error('Target hash generation failed:', error);
    }
  }

  // Test one candidate at a time so the learner can observe hashing and comparison.
  async function startAttack() {
    if (attackRunning) {
      return;
    }

    if (!isValidTargetHash(targetHash)) {
      attackStatus.textContent = 'Target hash required';
      attackResult.textContent = 'Generate a valid target hash before starting the attack.';
      return;
    }

    clearAttackOutput();
    attackRunning = true;
    const currentRunId = ++attackRunId;
    setButtonsForAttackState();
    attackStatus.textContent = 'Running';

    try {
      for (let index = 0; index < CANDIDATE_PASSWORDS.length; index += 1) {
        if (!attackRunning || currentRunId !== attackRunId) {
          return;
        }

        const candidate = CANDIDATE_PASSWORDS[index];
        const candidateHash = await sha256Hash(candidate);
        const matched = candidateHash === targetHash.toLowerCase();
        const attempts = index + 1;

        currentCandidate.textContent = candidate;
        attemptCount.textContent = String(attempts);
        attackProgress.value = (attempts / CANDIDATE_PASSWORDS.length) * 100;
        addAttackLogEntry(attempts, candidate, candidateHash, matched);

        if (matched) {
          attackProgress.value = 100;
          attackStatus.textContent = 'Password Found';
          attackResult.textContent = `A matching candidate was found after ${attempts} attempt${attempts === 1 ? '' : 's'}.`;
          attackRunning = false;
          setButtonsForAttackState();
          return;
        }

        await wait(600);
      }

      attackProgress.value = 100;
      attackStatus.textContent = 'Password Not Found';
      attackResult.textContent =
        `The target password was not present in the predefined dictionary. ` +
        `${CANDIDATE_PASSWORDS.length} attempts were made.`;
    } catch (error) {
      attackStatus.textContent = 'Error';
      attackResult.textContent = 'The attack could not be completed because hashing failed.';
      console.error('Dictionary attack simulation failed:', error);
    } finally {
      if (currentRunId === attackRunId) {
        attackRunning = false;
        setButtonsForAttackState();
      }
    }
  }

  function resetAttack() {
    attackRunId += 1;
    attackRunning = false;
    targetHash = '';
    targetPasswordInput.value = '';
    targetHashOutput.textContent = 'No target hash generated.';
    attackStatus.textContent = 'Ready to begin the dictionary attack.';
    clearAttackOutput();
    setButtonsForAttackState();
  }

  generateHashButton.addEventListener('click', generateTargetHash);
  startAttackButton.addEventListener('click', startAttack);
  resetAttackButton.addEventListener('click', resetAttack);
  setButtonsForAttackState();
}

function evaluateQuestion(questionFieldset) {
  const selectedAnswer = questionFieldset.querySelector('input[type="radio"]:checked');
  const feedback = questionFieldset.querySelector('.quiz-feedback');
  const correctAnswer = questionFieldset.dataset.correctAnswer;

  if (!feedback) {
    return false;
  }

  if (!selectedAnswer) {
    feedback.textContent = 'Not answered';
    return false;
  }

  const isCorrect = selectedAnswer.value === correctAnswer;
  feedback.textContent = isCorrect ? 'Correct' : 'Incorrect';
  return isCorrect;
}

function resetQuiz(questionFields, quizResult) {
  questionFields.forEach((questionFieldset) => {
    questionFieldset.querySelectorAll('input[type="radio"]').forEach((radio) => {
      radio.checked = false;
    });

    const feedback = questionFieldset.querySelector('.quiz-feedback');
    if (feedback) {
      feedback.textContent = '';
    }
  });

  quizResult.textContent = '';
}

function initializeQuiz() {
  const quizPanel = document.querySelector('#quiz .quiz-panel');
  const submitButton = document.getElementById('submit-quiz');
  const retryButton = document.getElementById('retry-quiz');
  const quizResult = document.getElementById('quiz-result');

  if (!quizPanel || !submitButton || !retryButton || !quizResult) {
    return;
  }

  const questionFields = Array.from(quizPanel.querySelectorAll('fieldset[data-correct-answer]'));

  questionFields.forEach((questionFieldset) => {
    const feedback = document.createElement('p');
    feedback.className = 'quiz-feedback';
    feedback.setAttribute('aria-live', 'polite');
    questionFieldset.appendChild(feedback);
  });

  function submitQuiz() {
    const score = questionFields.reduce(
      (total, questionFieldset) => total + (evaluateQuestion(questionFieldset) ? 1 : 0),
      0
    );
    const outcome = score >= 3 ? 'Passed' : 'Needs improvement';
    quizResult.textContent = `Score: ${score}/${questionFields.length}. ${outcome}.`;
  }

  submitButton.addEventListener('click', submitQuiz);
  retryButton.addEventListener('click', () => resetQuiz(questionFields, quizResult));
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initializeDictionaryAttackUI();
    initializeQuiz();
  });
} else {
  initializeDictionaryAttackUI();
  initializeQuiz();
}

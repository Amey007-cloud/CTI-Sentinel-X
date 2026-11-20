# Private GitHub Submission

Create a **private** repository for the final assessment. Do not upload `.env`, API keys, local uploads or database volumes.

From PowerShell in the project directory:

```powershell
git init
git add .
git status
git commit -m "Build CTI Sentinel X MongoDB final assessment"
git branch -M main
git remote add origin https://github.com/<YOUR-USERNAME>/<YOUR-PRIVATE-REPOSITORY>.git
git push -u origin main
```

Before pushing, confirm `.env` is ignored:

```powershell
git check-ignore .env
```

Add the faculty member as a collaborator using GitHub repository Settings → Collaborators. The repository must remain private as specified in the assessment brief. Submit the private repository URL in the PDF/assessment portal and send the collaboration request to faculty by the required remonstration deadline.


Before pushing the enhanced repository, run `git status` and confirm that `.env`, `recovery_backup/`, `data/raw/`, `data/processed/`, local model artifacts and training predictions are ignored. Do not commit MongoDB BSON dumps, checksums if they contain sensitive operational context, API keys, raw feeds or serialized model artifacts unless they are intentionally being published to the dedicated Hugging Face model repository. See `docs/URL_ML_CLASSIFIER.md` for the model workflow.

# wordpress-releases-github-action

This is a GitHub action to publish latest WordPress plugin builds to the dev environment. In most cases you should be
able to just create an additional step right after your `copy artifacts to s3` step like so.

```yaml
      - name: Publish Release to Latest WP
        id: publish_latest
        uses: bmlt-enabled/wordpress-releases-github-action@v1
        with:
          file: ${{ env.DIST_DIR_S3 }}/${{ env.ZIP_FILENAME }}
          aws_account_id: ${{ secrets.AWS_ACCOUNT_ID }}
          s3_key: ${{ env.S3_KEY }}
```

package github

import "github.com/google/jsonschema-go/jsonschema"

// Shared OutputSchema property builders for common go-github types.
// These ensure OutputSchema definitions stay complete and consistent
// across all tools that reference the same underlying types.
//
// Each function returns a fresh map so callers can safely modify it.

// UserSchemaProperties returns the JSON Schema properties for github.User.
func UserSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"login":                     {Type: "string"},
		"id":                        {Type: "integer"},
		"node_id":                   {Type: "string"},
		"avatar_url":                {Type: "string"},
		"html_url":                  {Type: "string"},
		"gravatar_id":               {Type: "string"},
		"name":                      {Type: "string"},
		"company":                   {Type: "string"},
		"blog":                      {Type: "string"},
		"location":                  {Type: "string"},
		"email":                     {Type: "string"},
		"hireable":                  {Type: "boolean"},
		"bio":                       {Type: "string"},
		"twitter_username":          {Type: "string"},
		"public_repos":              {Type: "integer"},
		"public_gists":              {Type: "integer"},
		"followers":                 {Type: "integer"},
		"following":                 {Type: "integer"},
		"created_at":                {Type: "string"},
		"updated_at":                {Type: "string"},
		"suspended_at":              {Type: "string"},
		"type":                      {Type: "string"},
		"site_admin":                {Type: "boolean"},
		"total_private_repos":       {Type: "integer"},
		"owned_private_repos":       {Type: "integer"},
		"private_gists":             {Type: "integer"},
		"disk_usage":                {Type: "integer"},
		"collaborators":             {Type: "integer"},
		"two_factor_authentication": {Type: "boolean"},
		"plan":                      {Type: "object"},
		"ldap_dn":                   {Type: "string"},
		"url":                       {Type: "string"},
		"events_url":                {Type: "string"},
		"following_url":             {Type: "string"},
		"followers_url":             {Type: "string"},
		"gists_url":                 {Type: "string"},
		"organizations_url":         {Type: "string"},
		"received_events_url":       {Type: "string"},
		"repos_url":                 {Type: "string"},
		"starred_url":               {Type: "string"},
		"subscriptions_url":         {Type: "string"},
		"text_matches":              {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
		"permissions":               {Type: "object"},
		"role_name":                 {Type: "string"},
		"assignment":                {Type: "string"},
		"inherited_from":            {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
	}
}

// UserSchema returns a JSON Schema object for github.User.
func UserSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:       "object",
		Properties: UserSchemaProperties(),
	}
}

// LabelSchemaProperties returns the JSON Schema properties for github.Label.
func LabelSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":          {Type: "integer"},
		"url":         {Type: "string"},
		"name":        {Type: "string"},
		"color":       {Type: "string"},
		"description": {Type: "string"},
		"default":     {Type: "boolean"},
		"node_id":     {Type: "string"},
	}
}

// IssueCommentSchemaProperties returns the JSON Schema properties for github.IssueComment.
func IssueCommentSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":                 {Type: "integer"},
		"node_id":            {Type: "string"},
		"body":               {Type: "string"},
		"user":               UserSchema(),
		"reactions":          {Type: "object"},
		"created_at":         {Type: "string"},
		"updated_at":         {Type: "string"},
		"author_association": {Type: "string"},
		"url":                {Type: "string"},
		"html_url":           {Type: "string"},
		"issue_url":          {Type: "string"},
	}
}

// CommitAuthorSchemaProperties returns the JSON Schema properties for github.CommitAuthor.
func CommitAuthorSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"date":     {Type: "string"},
		"name":     {Type: "string"},
		"email":    {Type: "string"},
		"username": {Type: "string"},
	}
}

// SignatureVerificationSchemaProperties returns the JSON Schema properties for github.SignatureVerification.
func SignatureVerificationSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"verified":  {Type: "boolean"},
		"reason":    {Type: "string"},
		"signature": {Type: "string"},
		"payload":   {Type: "string"},
	}
}

// CommitSchemaProperties returns the JSON Schema properties for github.Commit.
func CommitSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"sha": {Type: "string"},
		"author": {
			Type:       "object",
			Properties: CommitAuthorSchemaProperties(),
		},
		"committer": {
			Type:       "object",
			Properties: CommitAuthorSchemaProperties(),
		},
		"message":       {Type: "string"},
		"tree":          {Type: "object"},
		"parents":       {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
		"html_url":      {Type: "string"},
		"url":           {Type: "string"},
		"verification":  {Type: "object", Properties: SignatureVerificationSchemaProperties()},
		"node_id":       {Type: "string"},
		"comment_count": {Type: "integer"},
	}
}

// CommitFileSchemaProperties returns the JSON Schema properties for github.CommitFile.
func CommitFileSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"sha":               {Type: "string"},
		"filename":          {Type: "string"},
		"additions":         {Type: "integer"},
		"deletions":         {Type: "integer"},
		"changes":           {Type: "integer"},
		"status":            {Type: "string"},
		"patch":             {Type: "string"},
		"blob_url":          {Type: "string"},
		"raw_url":           {Type: "string"},
		"contents_url":      {Type: "string"},
		"previous_filename": {Type: "string"},
	}
}

// CommitStatsSchemaProperties returns the JSON Schema properties for github.CommitStats.
func CommitStatsSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"additions": {Type: "integer"},
		"deletions": {Type: "integer"},
		"total":     {Type: "integer"},
	}
}

// RepositoryContentSchemaProperties returns the JSON Schema properties for github.RepositoryContent.
func RepositoryContentSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"type":              {Type: "string"},
		"target":            {Type: "string"},
		"encoding":          {Type: "string"},
		"size":              {Type: "integer"},
		"name":              {Type: "string"},
		"path":              {Type: "string"},
		"content":           {Type: "string"},
		"sha":               {Type: "string"},
		"url":               {Type: "string"},
		"git_url":           {Type: "string"},
		"html_url":          {Type: "string"},
		"download_url":      {Type: "string"},
		"submodule_git_url": {Type: "string"},
	}
}

// RepositoryReleaseSchemaProperties returns the JSON Schema properties for github.RepositoryRelease.
func RepositoryReleaseSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"tag_name":                 {Type: "string"},
		"target_commitish":         {Type: "string"},
		"name":                     {Type: "string"},
		"body":                     {Type: "string"},
		"draft":                    {Type: "boolean"},
		"prerelease":               {Type: "boolean"},
		"make_latest":              {Type: "string"},
		"discussion_category_name": {Type: "string"},
		"generate_release_notes":   {Type: "boolean"},
		"id":                       {Type: "integer"},
		"created_at":               {Type: "string"},
		"published_at":             {Type: "string"},
		"url":                      {Type: "string"},
		"html_url":                 {Type: "string"},
		"assets_url":               {Type: "string"},
		"assets":                   {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
		"upload_url":               {Type: "string"},
		"zipball_url":              {Type: "string"},
		"tarball_url":              {Type: "string"},
		"author":                   UserSchema(),
		"node_id":                  {Type: "string"},
		"immutable":                {Type: "boolean"},
	}
}

// TagSchemaProperties returns the JSON Schema properties for github.Tag (git tag object).
func TagSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"tag":     {Type: "string"},
		"sha":     {Type: "string"},
		"url":     {Type: "string"},
		"message": {Type: "string"},
		"tagger": {
			Type:       "object",
			Properties: CommitAuthorSchemaProperties(),
		},
		"object": {
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"type": {Type: "string"},
				"sha":  {Type: "string"},
				"url":  {Type: "string"},
			},
		},
		"verification": {
			Type:       "object",
			Properties: SignatureVerificationSchemaProperties(),
		},
		"node_id": {Type: "string"},
	}
}

// PullRequestSchemaProperties returns the JSON Schema properties for github.PullRequest.
func PullRequestSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":                    {Type: "integer"},
		"number":                {Type: "integer"},
		"state":                 {Type: "string"},
		"locked":                {Type: "boolean"},
		"title":                 {Type: "string"},
		"body":                  {Type: "string"},
		"created_at":            {Type: "string"},
		"updated_at":            {Type: "string"},
		"closed_at":             {Type: "string"},
		"merged_at":             {Type: "string"},
		"labels":                {Type: "array", Items: &jsonschema.Schema{Type: "object", Properties: LabelSchemaProperties()}},
		"user":                  UserSchema(),
		"draft":                 {Type: "boolean"},
		"url":                   {Type: "string"},
		"html_url":              {Type: "string"},
		"issue_url":             {Type: "string"},
		"statuses_url":          {Type: "string"},
		"diff_url":              {Type: "string"},
		"patch_url":             {Type: "string"},
		"commits_url":           {Type: "string"},
		"comments_url":          {Type: "string"},
		"review_comments_url":   {Type: "string"},
		"review_comment_url":    {Type: "string"},
		"assignee":              UserSchema(),
		"assignees":             {Type: "array", Items: UserSchema()},
		"milestone":             {Type: "object"},
		"author_association":    {Type: "string"},
		"node_id":               {Type: "string"},
		"requested_reviewers":   {Type: "array", Items: UserSchema()},
		"auto_merge":            {Type: "object"},
		"merged":                {Type: "boolean"},
		"mergeable":             {Type: "boolean"},
		"mergeable_state":       {Type: "string"},
		"rebaseable":            {Type: "boolean"},
		"merged_by":             UserSchema(),
		"merge_commit_sha":      {Type: "string"},
		"comments":              {Type: "integer"},
		"commits":               {Type: "integer"},
		"additions":             {Type: "integer"},
		"deletions":             {Type: "integer"},
		"changed_files":         {Type: "integer"},
		"maintainer_can_modify": {Type: "boolean"},
		"review_comments":       {Type: "integer"},
		"requested_teams":       {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
		"_links":                {Type: "object"},
		"head":                  {Type: "object", Properties: PullRequestBranchSchemaProperties()},
		"base":                  {Type: "object", Properties: PullRequestBranchSchemaProperties()},
		"active_lock_reason":    {Type: "string"},
	}
}

// PullRequestBranchSchemaProperties returns the JSON Schema properties for github.PullRequestBranch.
func PullRequestBranchSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"label": {Type: "string"},
		"ref":   {Type: "string"},
		"sha":   {Type: "string"},
		"repo":  {Type: "object"},
		"user":  UserSchema(),
	}
}

// PullRequestReviewSchemaProperties returns the JSON Schema properties for github.PullRequestReview.
func PullRequestReviewSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":                 {Type: "integer"},
		"node_id":            {Type: "string"},
		"user":               UserSchema(),
		"body":               {Type: "string"},
		"submitted_at":       {Type: "string"},
		"commit_id":          {Type: "string"},
		"html_url":           {Type: "string"},
		"pull_request_url":   {Type: "string"},
		"state":              {Type: "string"},
		"author_association": {Type: "string"},
	}
}

// CombinedStatusSchemaProperties returns the JSON Schema properties for github.CombinedStatus.
func CombinedStatusSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"state":       {Type: "string"},
		"name":        {Type: "string"},
		"sha":         {Type: "string"},
		"total_count": {Type: "integer"},
		"statuses": {
			Type: "array",
			Items: &jsonschema.Schema{
				Type:       "object",
				Properties: RepoStatusSchemaProperties(),
			},
		},
		"commit_url":     {Type: "string"},
		"repository_url": {Type: "string"},
	}
}

// RepoStatusSchemaProperties returns the JSON Schema properties for github.RepoStatus.
func RepoStatusSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":          {Type: "integer"},
		"node_id":     {Type: "string"},
		"url":         {Type: "string"},
		"state":       {Type: "string"},
		"target_url":  {Type: "string"},
		"description": {Type: "string"},
		"context":     {Type: "string"},
		"avatar_url":  {Type: "string"},
		"creator":     UserSchema(),
		"created_at":  {Type: "string"},
		"updated_at":  {Type: "string"},
	}
}

// IssueSchemaProperties returns the JSON Schema properties for github.Issue.
func IssueSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":                 {Type: "integer"},
		"number":             {Type: "integer"},
		"state":              {Type: "string"},
		"state_reason":       {Type: "string"},
		"locked":             {Type: "boolean"},
		"title":              {Type: "string"},
		"body":               {Type: "string"},
		"author_association": {Type: "string"},
		"user":               UserSchema(),
		"labels":             {Type: "array", Items: &jsonschema.Schema{Type: "object", Properties: LabelSchemaProperties()}},
		"assignee":           UserSchema(),
		"comments":           {Type: "integer"},
		"closed_at":          {Type: "string"},
		"created_at":         {Type: "string"},
		"updated_at":         {Type: "string"},
		"closed_by":          UserSchema(),
		"url":                {Type: "string"},
		"html_url":           {Type: "string"},
		"comments_url":       {Type: "string"},
		"events_url":         {Type: "string"},
		"labels_url":         {Type: "string"},
		"repository_url":     {Type: "string"},
		"parent_issue_url":   {Type: "string"},
		"milestone":          {Type: "object"},
		"pull_request":       {Type: "object"},
		"repository":         {Type: "object"},
		"reactions":          {Type: "object"},
		"assignees":          {Type: "array", Items: UserSchema()},
		"node_id":            {Type: "string"},
		"draft":              {Type: "boolean"},
		"type":               {Type: "object"},
		"text_matches":       {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
		"active_lock_reason": {Type: "string"},
	}
}

// SubIssueSchemaProperties returns the JSON Schema properties for github.SubIssue.
func SubIssueSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":                 {Type: "integer"},
		"number":             {Type: "integer"},
		"state":              {Type: "string"},
		"state_reason":       {Type: "string"},
		"locked":             {Type: "boolean"},
		"title":              {Type: "string"},
		"body":               {Type: "string"},
		"author_association": {Type: "string"},
		"user":               UserSchema(),
		"labels":             {Type: "array", Items: &jsonschema.Schema{Type: "object", Properties: LabelSchemaProperties()}},
		"assignee":           UserSchema(),
		"comments":           {Type: "integer"},
		"closed_at":          {Type: "string"},
		"created_at":         {Type: "string"},
		"updated_at":         {Type: "string"},
		"closed_by":          UserSchema(),
		"url":                {Type: "string"},
		"html_url":           {Type: "string"},
		"comments_url":       {Type: "string"},
		"events_url":         {Type: "string"},
		"labels_url":         {Type: "string"},
		"repository_url":     {Type: "string"},
		"parent_issue_url":   {Type: "string"},
		"milestone":          {Type: "object"},
		"pull_request":       {Type: "object"},
		"repository":         {Type: "object"},
		"reactions":          {Type: "object"},
		"assignees":          {Type: "array", Items: UserSchema()},
		"node_id":            {Type: "string"},
		"draft":              {Type: "boolean"},
		"type":               {Type: "object"},
		"text_matches":       {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
		"active_lock_reason": {Type: "string"},
	}
}

// IssueTypeSchemaProperties returns the JSON Schema properties for github.IssueType.
func IssueTypeSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":          {Type: "integer"},
		"node_id":     {Type: "string"},
		"name":        {Type: "string"},
		"description": {Type: "string"},
		"color":       {Type: "string"},
		"created_at":  {Type: "string"},
		"updated_at":  {Type: "string"},
	}
}

// ReactionsSchemaProperties returns the JSON Schema properties for github.Reactions.
func ReactionsSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"total_count": {Type: "integer"},
		"+1":          {Type: "integer"},
		"-1":          {Type: "integer"},
		"laugh":       {Type: "integer"},
		"confused":    {Type: "integer"},
		"heart":       {Type: "integer"},
		"hooray":      {Type: "integer"},
		"rocket":      {Type: "integer"},
		"eyes":        {Type: "integer"},
		"url":         {Type: "string"},
	}
}

// MinimalUserSchema returns a JSON Schema for MinimalUser (used in custom result types).
func MinimalUserSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"login":       {Type: "string"},
			"id":          {Type: "integer"},
			"profile_url": {Type: "string"},
			"avatar_url":  {Type: "string"},
			"details":     {Type: "object"},
		},
	}
}

// GistSchemaProperties returns the JSON Schema properties for github.Gist.
func GistSchemaProperties() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"id":           {Type: "string"},
		"description":  {Type: "string"},
		"public":       {Type: "boolean"},
		"owner":        MinimalUserSchema(),
		"files":        {Type: "object"},
		"comments":     {Type: "integer"},
		"html_url":     {Type: "string"},
		"git_pull_url": {Type: "string"},
		"git_push_url": {Type: "string"},
		"created_at":   {Type: "string"},
		"updated_at":   {Type: "string"},
		"node_id":      {Type: "string"},
	}
}

module ApplicationHelper
  def get_metadata(endpoint)
    conn = Faraday.new endpoint, :ssl => {:verify => false}
    conn.get.body
  end
end

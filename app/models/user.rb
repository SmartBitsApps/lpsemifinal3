class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,:confirmable, :lockable,
          :recoverable, :rememberable, :trackable, :validatable
          
          
  # Devise validates email and password automatically
  validates_presence_of :first_name
  validates_presence_of :last_name
  
  enum role: [:pending, :user, :manager, :admin]
  enum status: [:banned, :inactive, :active]
  
  # sets default settings and build account for user
  after_initialize :set_default_role_and_status, :if => :new_record?
  #after_initialize :build_new_account, :if => :new_record?
  
  def set_default_role_and_status
    self.role ||= :pending
    self.status ||= :inactive
  end
end
